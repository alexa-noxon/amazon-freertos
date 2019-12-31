/*
 * Amazon FreeRTOS V201910.00
 * Copyright (C) 2018 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */


/**
 * @file aws_dev_mode_key_provisioning.c
 * @brief Simple key provisioning example using PKCS #11
 *
 * A simple example to demonstrate key and certificate provisioning in
 * flash using PKCS #11 interface. This should be replaced
 * by production ready key provisioning mechanism.
 */

/* Standard includes. */
#include <stdio.h>
#include <string.h>

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"

/* PKCS#11 includes. */
#include "iot_pkcs11_config.h"
#include "iot_pkcs11.h"

/* Client credential includes. */
#include "aws_clientcredential.h"
#include "aws_clientcredential_keys.h"
#include "iot_default_root_certificates.h"

/* Key provisioning include. */
#include "aws_dev_mode_key_provisioning.h"

/* Utilities include. */
#include "iot_pki_utils.h"

/* mbedTLS includes. */

#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/pk_internal.h"
#include "mbedtls/oid.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509_crt.h"

/* Default Amazon FreeRTOS API for console logging. */
#define DEV_MODE_KEY_PROVISIONING_PRINT( X )    vLoggingPrintf X

/* For writing log lines without a prefix. */
extern void vLoggingPrint( const char * pcFormat );

/* Developer convenience override, for lab testing purposes, for generating
 * a new default key pair, regardless of whether an existing key pair is present. */
#define keyprovisioningFORCE_GENERATE_NEW_KEY_PAIR    0

/* Internal structure for parsing RSA keys. */

/* Length parameters for importing RSA-2048 private keys. */
#define MODULUS_LENGTH        pkcs11RSA_2048_MODULUS_BITS / 8
#define E_LENGTH              3
#define D_LENGTH              pkcs11RSA_2048_MODULUS_BITS / 8
#define PRIME_1_LENGTH        128
#define PRIME_2_LENGTH        128
#define EXPONENT_1_LENGTH     128
#define EXPONENT_2_LENGTH     128
#define COEFFICIENT_LENGTH    128

/* Adding one to all of the lengths because ASN1 may pad a leading 0 byte
 * to numbers that could be interpreted as negative */
typedef struct RsaParams_t
{
    CK_BYTE modulus[ MODULUS_LENGTH + 1 ];
    CK_BYTE e[ E_LENGTH + 1 ];
    CK_BYTE d[ D_LENGTH + 1 ];
    CK_BYTE prime1[ PRIME_1_LENGTH + 1 ];
    CK_BYTE prime2[ PRIME_2_LENGTH + 1 ];
    CK_BYTE exponent1[ EXPONENT_1_LENGTH + 1 ];
    CK_BYTE exponent2[ EXPONENT_2_LENGTH + 1 ];
    CK_BYTE coefficient[ COEFFICIENT_LENGTH + 1 ];
} RsaParams_t;

/* Internal structure for capturing the privisioned state of the host device. */
typedef struct ProvisionedState_t
{
    CK_OBJECT_HANDLE xPrivateKey;
    CK_OBJECT_HANDLE xClientCertificate;
    CK_OBJECT_HANDLE xPublicKey;
    uint8_t * pucDerPublicKey;
    uint32_t ulDerPublicKeyLength;
    char * pcIdentifier; /* The token label. On some devices, a unique device
                          * ID might be stored here which can be used as a field
                          * in the subject of the device certificate. */
} ProvisionedState_t;

/* This function can be found in libraries/3rdparty/mbedtls/utils/mbedtls_utils.c. */
extern int convert_pem_to_der( const unsigned char * pucInput,
                               size_t xLen,
                               unsigned char * pucOutput,
                               size_t * pxOlen );

/*-----------------------------------------------------------*/

/* Import the specified ECDSA private key into storage. */
static CK_RV prvProvisionPrivateECKey( CK_SESSION_HANDLE xSession,
                                       uint8_t * pucLabel,
                                       CK_OBJECT_HANDLE_PTR pxObjectHandle,
                                       mbedtls_pk_context * pxMbedPkContext )
{
    CK_RV xResult = CKR_OK;
    CK_FUNCTION_LIST_PTR pxFunctionList = NULL;
    CK_BYTE * pxD;               /* Private value D. */
    CK_BYTE * pxEcParams = NULL; /* DER-encoding of an ANSI X9.62 Parameters value */
    int lMbedResult = 0;
    CK_BBOOL xTrue = CK_TRUE;
    CK_KEY_TYPE xPrivateKeyType = CKK_EC;
    CK_OBJECT_CLASS xPrivateKeyClass = CKO_PRIVATE_KEY;
    mbedtls_ecp_keypair * pxKeyPair = ( mbedtls_ecp_keypair * ) pxMbedPkContext->pk_ctx;

    xResult = C_GetFunctionList( &pxFunctionList );

#define EC_PARAMS_LENGTH    10
#define EC_D_LENGTH         32

    pxD = pvPortMalloc( EC_D_LENGTH );

    if( ( pxD == NULL ) )
    {
        xResult = CKR_HOST_MEMORY;
    }

    if( xResult == CKR_OK )
    {
        lMbedResult = mbedtls_mpi_write_binary( &( pxKeyPair->d ), pxD, EC_D_LENGTH );

        if( lMbedResult != 0 )
        {
            DEV_MODE_KEY_PROVISIONING_PRINT( ( "Failed to parse EC private key components. \r\n" ) );
            xResult = CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }

    if( xResult == CKR_OK )
    {
        if( pxKeyPair->grp.id == MBEDTLS_ECP_DP_SECP256R1 )
        {
            pxEcParams = ( CK_BYTE * ) ( "\x06\x08" MBEDTLS_OID_EC_GRP_SECP256R1 );
        }
        else
        {
            xResult = CKR_CURVE_NOT_SUPPORTED;
        }
    }

    if( xResult == CKR_OK )
    {
        CK_ATTRIBUTE xPrivateKeyTemplate[] =
        {
            { CKA_CLASS,     &xPrivateKeyClass, sizeof( CK_OBJECT_CLASS )                        },
            { CKA_KEY_TYPE,  &xPrivateKeyType,  sizeof( CK_KEY_TYPE )                            },
            { CKA_LABEL,     pucLabel,          ( CK_ULONG ) strlen( ( const char * ) pucLabel ) },
            { CKA_TOKEN,     &xTrue,            sizeof( CK_BBOOL )                               },
            { CKA_SIGN,      &xTrue,            sizeof( CK_BBOOL )                               },
            { CKA_EC_PARAMS, pxEcParams,        EC_PARAMS_LENGTH                                 },
            { CKA_VALUE,     pxD,               EC_D_LENGTH                                      }
        };

        xResult = pxFunctionList->C_CreateObject( xSession,
                                                  ( CK_ATTRIBUTE_PTR ) &xPrivateKeyTemplate,
                                                  sizeof( xPrivateKeyTemplate ) / sizeof( CK_ATTRIBUTE ),
                                                  pxObjectHandle );
    }

    if( pxD != NULL )
    {
        vPortFree( pxD );
    }

    return xResult;
}

/*-----------------------------------------------------------*/

/* Import the specified RSA private key into storage. */
static CK_RV prvProvisionPrivateRSAKey( CK_SESSION_HANDLE xSession,
                                        uint8_t * pucLabel,
                                        CK_OBJECT_HANDLE_PTR pxObjectHandle,
                                        mbedtls_pk_context * pxMbedPkContext )
{
    CK_RV xResult = CKR_OK;
    CK_FUNCTION_LIST_PTR pxFunctionList = NULL;
    int lMbedResult = 0;
    CK_KEY_TYPE xPrivateKeyType = CKK_RSA;
    mbedtls_rsa_context * xRsaContext = pxMbedPkContext->pk_ctx;
    CK_OBJECT_CLASS xPrivateKeyClass = CKO_PRIVATE_KEY;
    RsaParams_t * pxRsaParams = NULL;
    CK_BBOOL xTrue = CK_TRUE;

    xResult = C_GetFunctionList( &pxFunctionList );

    pxRsaParams = pvPortMalloc( sizeof( RsaParams_t ) );

    if( pxRsaParams == NULL )
    {
        xResult = CKR_HOST_MEMORY;
    }

    if( xResult == CKR_OK )
    {
        memset( pxRsaParams, 0, sizeof( RsaParams_t ) );

        lMbedResult = mbedtls_rsa_export_raw( xRsaContext,
                                              pxRsaParams->modulus, MODULUS_LENGTH + 1,
                                              pxRsaParams->prime1, PRIME_1_LENGTH + 1,
                                              pxRsaParams->prime2, PRIME_2_LENGTH + 1,
                                              pxRsaParams->d, D_LENGTH + 1,
                                              pxRsaParams->e, E_LENGTH + 1 );

        if( lMbedResult != 0 )
        {
            DEV_MODE_KEY_PROVISIONING_PRINT( ( "Failed to parse RSA private key components. \r\n" ) );
            xResult = CKR_ATTRIBUTE_VALUE_INVALID;
        }

        /* Export Exponent 1, Exponent 2, Coefficient. */
        lMbedResult |= mbedtls_mpi_write_binary( ( mbedtls_mpi const * ) &xRsaContext->DP, pxRsaParams->exponent1, EXPONENT_1_LENGTH + 1 );
        lMbedResult |= mbedtls_mpi_write_binary( ( mbedtls_mpi const * ) &xRsaContext->DQ, pxRsaParams->exponent2, EXPONENT_2_LENGTH + 1 );
        lMbedResult |= mbedtls_mpi_write_binary( ( mbedtls_mpi const * ) &xRsaContext->QP, pxRsaParams->coefficient, COEFFICIENT_LENGTH + 1 );

        if( lMbedResult != 0 )
        {
            DEV_MODE_KEY_PROVISIONING_PRINT( ( "Failed to parse RSA private key Chinese Remainder Theorem variables. \r\n" ) );
            xResult = CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }

    if( xResult == CKR_OK )
    {
        /* When importing the fields, the pointer is incremented by 1
         * to remove the leading 0 padding (if it existed) and the original field length is used */


        CK_ATTRIBUTE xPrivateKeyTemplate[] =
        {
            { CKA_CLASS,            &xPrivateKeyClass,            sizeof( CK_OBJECT_CLASS )                        },
            { CKA_KEY_TYPE,         &xPrivateKeyType,             sizeof( CK_KEY_TYPE )                            },
            { CKA_LABEL,            pucLabel,                     ( CK_ULONG ) strlen( ( const char * ) pucLabel ) },
            { CKA_TOKEN,            &xTrue,                       sizeof( CK_BBOOL )                               },
            { CKA_SIGN,             &xTrue,                       sizeof( CK_BBOOL )                               },
            { CKA_MODULUS,          pxRsaParams->modulus + 1,     MODULUS_LENGTH                                   },
            { CKA_PRIVATE_EXPONENT, pxRsaParams->d + 1,           D_LENGTH                                         },
            { CKA_PUBLIC_EXPONENT,  pxRsaParams->e + 1,           E_LENGTH                                         },
            { CKA_PRIME_1,          pxRsaParams->prime1 + 1,      PRIME_1_LENGTH                                   },
            { CKA_PRIME_2,          pxRsaParams->prime2 + 1,      PRIME_2_LENGTH                                   },
            { CKA_EXPONENT_1,       pxRsaParams->exponent1 + 1,   EXPONENT_1_LENGTH                                },
            { CKA_EXPONENT_2,       pxRsaParams->exponent2 + 1,   EXPONENT_2_LENGTH                                },
            { CKA_COEFFICIENT,      pxRsaParams->coefficient + 1, COEFFICIENT_LENGTH                               }
        };

        xResult = pxFunctionList->C_CreateObject( xSession,
                                                  ( CK_ATTRIBUTE_PTR ) &xPrivateKeyTemplate,
                                                  sizeof( xPrivateKeyTemplate ) / sizeof( CK_ATTRIBUTE ),
                                                  pxObjectHandle );
    }

    if( NULL != pxRsaParams )
    {
        vPortFree( pxRsaParams );
    }

    return xResult;
}

/*-----------------------------------------------------------*/

/* Import the specified private key into storage. */
CK_RV xProvisionPrivateKey( CK_SESSION_HANDLE xSession,
                            uint8_t * pucPrivateKey,
                            size_t xPrivateKeyLength,
                            uint8_t * pucLabel,
                            CK_OBJECT_HANDLE_PTR pxObjectHandle )
{
    CK_RV xResult = CKR_OK;
    mbedtls_pk_type_t xMbedKeyType = MBEDTLS_PK_NONE;
    int lMbedResult = 0;
    mbedtls_pk_context xMbedPkContext = { 0 };

    mbedtls_pk_init( &xMbedPkContext );
    lMbedResult = mbedtls_pk_parse_key( &xMbedPkContext, pucPrivateKey, xPrivateKeyLength, NULL, 0 );

    if( lMbedResult != 0 )
    {
        DEV_MODE_KEY_PROVISIONING_PRINT( ( "Unable to parse private key.\r\n" ) );
        xResult = CKR_ARGUMENTS_BAD;
    }

    /* Determine whether the key to be imported is RSA or EC. */
    if( xResult == CKR_OK )
    {
        xMbedKeyType = mbedtls_pk_get_type( &xMbedPkContext );

        if( xMbedKeyType == MBEDTLS_PK_RSA )
        {
            xResult = prvProvisionPrivateRSAKey( xSession,
                                                 pucLabel,
                                                 pxObjectHandle,
                                                 &xMbedPkContext );
        }
        else if( ( xMbedKeyType == MBEDTLS_PK_ECDSA ) || ( xMbedKeyType == MBEDTLS_PK_ECKEY ) || ( xMbedKeyType == MBEDTLS_PK_ECKEY_DH ) )
        {
            xResult = prvProvisionPrivateECKey( xSession,
                                                pucLabel,
                                                pxObjectHandle,
                                                &xMbedPkContext );
        }
        else
        {
            DEV_MODE_KEY_PROVISIONING_PRINT( ( "Invalid private key type provided.  RSA-2048 and EC P-256 keys are supported.\r\n" ) );
            xResult = CKR_ARGUMENTS_BAD;
        }
    }

    mbedtls_pk_free( &xMbedPkContext );

    return xResult;
}

/*-----------------------------------------------------------*/

/* Import the specified public key into storage. */
CK_RV xProvisionPublicKey( CK_SESSION_HANDLE xSession,
                           uint8_t * pucKey,
                           size_t xKeyLength,
                           CK_KEY_TYPE xPublicKeyType,
                           uint8_t * pucPublicKeyLabel,
                           CK_OBJECT_HANDLE_PTR pxPublicKeyHandle )
{
    CK_RV xResult;
    CK_BBOOL xTrue = CK_TRUE;
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_OBJECT_CLASS xClass = CKO_PUBLIC_KEY;
    int lMbedResult = 0;
    mbedtls_pk_context xMbedPkContext = { 0 };

    xResult = C_GetFunctionList( &pxFunctionList );

    mbedtls_pk_init( &xMbedPkContext );

    /* Try parsing the private key using mbedtls_pk_parse_key. */
    lMbedResult = mbedtls_pk_parse_key( &xMbedPkContext, pucKey, xKeyLength, NULL, 0 );

    /* If mbedtls_pk_parse_key didn't work, maybe the private key is not included in the input passed in.
     * Try to parse just the public key. */
    if( lMbedResult != 0 )
    {
        lMbedResult = mbedtls_pk_parse_public_key( &xMbedPkContext, pucKey, xKeyLength );
    }

    if( lMbedResult != 0 )
    {
        DEV_MODE_KEY_PROVISIONING_PRINT( ( "Failed to parse the public key. \r\n" ) );
        xResult = CKR_ARGUMENTS_BAD;
    }

    if( ( xResult == CKR_OK ) && ( xPublicKeyType == CKK_RSA ) )
    {
        CK_BYTE xPublicExponent[] = { 0x01, 0x00, 0x01 };
        CK_BYTE xModulus[ MODULUS_LENGTH + 1 ] = { 0 };

        lMbedResult = mbedtls_rsa_export_raw( ( mbedtls_rsa_context * ) xMbedPkContext.pk_ctx,
                                              ( unsigned char * ) &xModulus, MODULUS_LENGTH + 1,
                                              NULL, 0,
                                              NULL, 0,
                                              NULL, 0,
                                              NULL, 0 );
        CK_ATTRIBUTE xPublicKeyTemplate[] =
        {
            { CKA_CLASS,           &xClass,           sizeof( CK_OBJECT_CLASS )                    },
            { CKA_KEY_TYPE,        &xPublicKeyType,   sizeof( CK_KEY_TYPE )                        },
            { CKA_TOKEN,           &xTrue,            sizeof( xTrue )                              },
            { CKA_MODULUS,         &xModulus + 1,     MODULUS_LENGTH                               },     /* Extra byte allocated at beginning for 0 padding. */
            { CKA_VERIFY,          &xTrue,            sizeof( xTrue )                              },
            { CKA_PUBLIC_EXPONENT, xPublicExponent,   sizeof( xPublicExponent )                    },
            { CKA_LABEL,           pucPublicKeyLabel, strlen( ( const char * ) pucPublicKeyLabel ) }
        };

        xResult = pxFunctionList->C_CreateObject( xSession,
                                                  ( CK_ATTRIBUTE_PTR ) xPublicKeyTemplate,
                                                  sizeof( xPublicKeyTemplate ) / sizeof( CK_ATTRIBUTE ),
                                                  pxPublicKeyHandle );
    }
    else if( ( xResult == CKR_OK ) && ( xPublicKeyType == CKK_EC ) )
    {
        CK_BYTE xEcParams[] = pkcs11DER_ENCODED_OID_P256;
        size_t xLength;
        CK_BYTE xEcPoint[ 256 ] = { 0 };

        mbedtls_ecdsa_context * pxEcdsaContext = ( mbedtls_ecdsa_context * ) xMbedPkContext.pk_ctx;

        /* DER encoded EC point. Leave 2 bytes for the tag and length. */
        lMbedResult = mbedtls_ecp_point_write_binary( &pxEcdsaContext->grp,
                                                      &pxEcdsaContext->Q,
                                                      MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                      &xLength,
                                                      xEcPoint + 2,
                                                      sizeof( xEcPoint ) - 2 );
        xEcPoint[ 0 ] = 0x04; /* Octet string. */
        xEcPoint[ 1 ] = ( CK_BYTE ) xLength;

        CK_ATTRIBUTE xPublicKeyTemplate[] =
        {
            { CKA_CLASS,     &xClass,           sizeof( xClass )                             },
            { CKA_KEY_TYPE,  &xPublicKeyType,   sizeof( xPublicKeyType )                     },
            { CKA_TOKEN,     &xTrue,            sizeof( xTrue )                              },
            { CKA_VERIFY,    &xTrue,            sizeof( xTrue )                              },
            { CKA_EC_PARAMS, xEcParams,         sizeof( xEcParams )                          },
            { CKA_EC_POINT,  xEcPoint,          xLength + 2                                  },
            { CKA_LABEL,     pucPublicKeyLabel, strlen( ( const char * ) pucPublicKeyLabel ) }
        };

        xResult = pxFunctionList->C_CreateObject( xSession,
                                                  ( CK_ATTRIBUTE_PTR ) xPublicKeyTemplate,
                                                  sizeof( xPublicKeyTemplate ) / sizeof( CK_ATTRIBUTE ),
                                                  pxPublicKeyHandle );
    }
    else
    {
        xResult = CKR_ATTRIBUTE_VALUE_INVALID;
        configPRINTF( ( "Invalid key type. Supported options are CKK_RSA and CKK_EC" ) );
    }

    mbedtls_pk_free( &xMbedPkContext );

    return xResult;
}

/*-----------------------------------------------------------*/

/* Generate a new 2048-bit RSA key pair. Please note that C_GenerateKeyPair for
 * RSA keys is not supported by the Amazon FreeRTOS mbedTLS PKCS #11 port. */
CK_RV xProvisionGenerateKeyPairRSA( CK_SESSION_HANDLE xSession,
                                    uint8_t * pucPrivateKeyLabel,
                                    uint8_t * pucPublicKeyLabel,
                                    CK_OBJECT_HANDLE_PTR pxPrivateKeyHandle,
                                    CK_OBJECT_HANDLE_PTR pxPublicKeyHandle )
{
    CK_RV xResult;
    CK_MECHANISM xMechanism =
    {
        CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
    };
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_ULONG xModulusBits = pkcs11RSA_2048_MODULUS_BITS;
    CK_BYTE xPublicExponent[] = pkcs11RSA_PUBLIC_EXPONENT;

    CK_BBOOL xTrue = CK_TRUE;
    CK_ATTRIBUTE xPublicKeyTemplate[] =
    {
        { CKA_ENCRYPT,         &xTrue,            sizeof( xTrue )                              },
        { CKA_VERIFY,          &xTrue,            sizeof( xTrue )                              },
        { CKA_MODULUS_BITS,    &xModulusBits,     sizeof( xModulusBits )                       },
        { CKA_PUBLIC_EXPONENT, xPublicExponent,   sizeof( xPublicExponent )                    },
        { CKA_LABEL,           pucPublicKeyLabel, strlen( ( const char * ) pucPublicKeyLabel ) }
    };

    CK_ATTRIBUTE xPrivateKeyTemplate[] =
    {
        { CKA_TOKEN,   &xTrue,             sizeof( xTrue )                               },
        { CKA_PRIVATE, &xTrue,             sizeof( xTrue )                               },
        { CKA_DECRYPT, &xTrue,             sizeof( xTrue )                               },
        { CKA_SIGN,    &xTrue,             sizeof( xTrue )                               },
        { CKA_LABEL,   pucPrivateKeyLabel, strlen( ( const char * ) pucPrivateKeyLabel ) }
    };

    xResult = C_GetFunctionList( &pxFunctionList );

    xResult = pxFunctionList->C_GenerateKeyPair( xSession,
                                                 &xMechanism,
                                                 xPublicKeyTemplate,
                                                 sizeof( xPublicKeyTemplate ) / sizeof( CK_ATTRIBUTE ),
                                                 xPrivateKeyTemplate, sizeof( xPrivateKeyTemplate ) / sizeof( CK_ATTRIBUTE ),
                                                 pxPublicKeyHandle,
                                                 pxPrivateKeyHandle );

    return xResult;
}

/*-----------------------------------------------------------*/

/* Generate a new ECDSA key pair using curve P256. */
CK_RV xProvisionGenerateKeyPairEC( CK_SESSION_HANDLE xSession,
                                   uint8_t * pucPrivateKeyLabel,
                                   uint8_t * pucPublicKeyLabel,
                                   CK_OBJECT_HANDLE_PTR pxPrivateKeyHandle,
                                   CK_OBJECT_HANDLE_PTR pxPublicKeyHandle )
{
    CK_RV xResult;
    CK_MECHANISM xMechanism =
    {
        CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0
    };
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_BYTE xEcParams[] = pkcs11DER_ENCODED_OID_P256; /* prime256v1 */
    CK_KEY_TYPE xKeyType = CKK_EC;

    CK_BBOOL xTrue = CK_TRUE;
    CK_ATTRIBUTE xPublicKeyTemplate[] =
    {
        { CKA_KEY_TYPE,  &xKeyType,         sizeof( xKeyType )                           },
        { CKA_VERIFY,    &xTrue,            sizeof( xTrue )                              },
        { CKA_EC_PARAMS, xEcParams,         sizeof( xEcParams )                          },
        { CKA_LABEL,     pucPublicKeyLabel, strlen( ( const char * ) pucPublicKeyLabel ) }
    };

    CK_ATTRIBUTE xPrivateKeyTemplate[] =
    {
        { CKA_KEY_TYPE, &xKeyType,          sizeof( xKeyType )                            },
        { CKA_TOKEN,    &xTrue,             sizeof( xTrue )                               },
        { CKA_PRIVATE,  &xTrue,             sizeof( xTrue )                               },
        { CKA_SIGN,     &xTrue,             sizeof( xTrue )                               },
        { CKA_LABEL,    pucPrivateKeyLabel, strlen( ( const char * ) pucPrivateKeyLabel ) }
    };

    xResult = C_GetFunctionList( &pxFunctionList );

    xResult = pxFunctionList->C_GenerateKeyPair( xSession,
                                                 &xMechanism,
                                                 xPublicKeyTemplate,
                                                 sizeof( xPublicKeyTemplate ) / sizeof( CK_ATTRIBUTE ),
                                                 xPrivateKeyTemplate, sizeof( xPrivateKeyTemplate ) / sizeof( CK_ATTRIBUTE ),
                                                 pxPublicKeyHandle,
                                                 pxPrivateKeyHandle );

    return xResult;
}

/*-----------------------------------------------------------*/

/* Import the specified X.509 client certificate into storage. */
CK_RV xProvisionCertificate( CK_SESSION_HANDLE xSession,
                             uint8_t * pucCertificate,
                             size_t xCertificateLength,
                             uint8_t * pucLabel,
                             CK_OBJECT_HANDLE_PTR pxObjectHandle )
{
    PKCS11_CertificateTemplate_t xCertificateTemplate;
    CK_OBJECT_CLASS xCertificateClass = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE xCertificateType = CKC_X_509;
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_RV xResult;
    uint8_t * pucDerObject = NULL;
    int32_t lConversionReturn = 0;
    size_t xDerLen = 0;
    CK_BBOOL xTokenStorage = CK_TRUE;

    /* TODO: Subject is a required attribute.
     * Currently, this field is not used by Amazon FreeRTOS ports,
     * this should be updated so that subject matches proper
     * format for future ports. */
    CK_BYTE xSubject[] = "TestSubject";

    /* Initialize the client certificate template. */
    xCertificateTemplate.xObjectClass.type = CKA_CLASS;
    xCertificateTemplate.xObjectClass.pValue = &xCertificateClass;
    xCertificateTemplate.xObjectClass.ulValueLen = sizeof( xCertificateClass );
    xCertificateTemplate.xSubject.type = CKA_SUBJECT;
    xCertificateTemplate.xSubject.pValue = xSubject;
    xCertificateTemplate.xSubject.ulValueLen = strlen( ( const char * ) xSubject );
    xCertificateTemplate.xValue.type = CKA_VALUE;
    xCertificateTemplate.xValue.pValue = ( CK_VOID_PTR ) pucCertificate;
    xCertificateTemplate.xValue.ulValueLen = ( CK_ULONG ) xCertificateLength;
    xCertificateTemplate.xLabel.type = CKA_LABEL;
    xCertificateTemplate.xLabel.pValue = ( CK_VOID_PTR ) pucLabel;
    xCertificateTemplate.xLabel.ulValueLen = strlen( ( const char * ) pucLabel );
    xCertificateTemplate.xCertificateType.type = CKA_CERTIFICATE_TYPE;
    xCertificateTemplate.xCertificateType.pValue = &xCertificateType;
    xCertificateTemplate.xCertificateType.ulValueLen = sizeof( CK_CERTIFICATE_TYPE );
    xCertificateTemplate.xTokenObject.type = CKA_TOKEN;
    xCertificateTemplate.xTokenObject.pValue = &xTokenStorage;
    xCertificateTemplate.xTokenObject.ulValueLen = sizeof( xTokenStorage );

    xResult = C_GetFunctionList( &pxFunctionList );

    /* Litmus test for valid certificiate.  0x2d is '-' as in ----- BEGIN CERTIFICATE ----- */
    if( ( pucCertificate == NULL ) || ( pucCertificate[ 0 ] != 0x2d ) )
    {
        xResult = CKR_ATTRIBUTE_VALUE_INVALID;
    }

    if( xResult == CKR_OK )
    {
        /* Convert the certificate to DER format if it was in PEM. */
        /* The DER key should be about 3/4 the size of the PEM key, so mallocing the PEM key size is sufficient. */
        pucDerObject = pvPortMalloc( xCertificateTemplate.xValue.ulValueLen );
        xDerLen = xCertificateTemplate.xValue.ulValueLen;

        if( pucDerObject != NULL )
        {
            lConversionReturn = convert_pem_to_der( xCertificateTemplate.xValue.pValue,
                                                    xCertificateTemplate.xValue.ulValueLen,
                                                    pucDerObject,
                                                    &xDerLen );

            if( 0 != lConversionReturn )
            {
                xResult = CKR_ARGUMENTS_BAD;
            }
        }
        else
        {
            xResult = CKR_HOST_MEMORY;
        }
    }

    if( xResult == CKR_OK )
    {
        /* Set the template pointers to refer to the DER converted objects. */
        xCertificateTemplate.xValue.pValue = pucDerObject;
        xCertificateTemplate.xValue.ulValueLen = xDerLen;
    }

    /* Best effort clean-up of the existing object, if it exists. */
    if( xResult == CKR_OK )
    {
        xDestroyProvidedObjects( xSession,
                                 &pucLabel,
                                 &xCertificateClass,
                                 1 );
    }

    /* Create an object using the encoded client certificate. */
    if( xResult == CKR_OK )
    {
        configPRINTF( ( "Write certificate...\r\n" ) );

        xResult = pxFunctionList->C_CreateObject( xSession,
                                                  ( CK_ATTRIBUTE_PTR ) &xCertificateTemplate,
                                                  sizeof( xCertificateTemplate ) / sizeof( CK_ATTRIBUTE ),
                                                  pxObjectHandle );
    }

    if( pucDerObject != NULL )
    {
        vPortFree( pucDerObject );
    }

    return xResult;
}

/*-----------------------------------------------------------*/

/* Delete the specified crypto object from storage. */
CK_RV xDestroyProvidedObjects( CK_SESSION_HANDLE xSession,
                               CK_BYTE_PTR * ppxPkcsLabels,
                               CK_OBJECT_CLASS * xClass,
                               CK_ULONG ulCount )
{
    CK_RV xResult;
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_OBJECT_HANDLE xObjectHandle;
    CK_BYTE * pxLabel;
    CK_ULONG uiIndex = 0;

    xResult = C_GetFunctionList( &pxFunctionList );

    for( uiIndex = 0; uiIndex < ulCount; uiIndex++ )
    {
        pxLabel = ppxPkcsLabels[ uiIndex ];

        xResult = xFindObjectWithLabelAndClass( xSession,
                                                ( const char * ) pxLabel,
                                                xClass[ uiIndex ],
                                                &xObjectHandle );

        while( ( xResult == CKR_OK ) && ( xObjectHandle != CK_INVALID_HANDLE ) )
        {
            xResult = pxFunctionList->C_DestroyObject( xSession, xObjectHandle );

            /* PKCS #11 allows a module to maintain multiple objects with the same
             * label and type. The intent of this loop is to try to delete all of them.
             * However, to avoid getting stuck, we won't try to find another object
             * of the same label/type if the previous delete failed. */
            if( xResult == CKR_OK )
            {
                xResult = xFindObjectWithLabelAndClass( xSession,
                                                        ( const char * ) pxLabel,
                                                        xClass[ uiIndex ],
                                                        &xObjectHandle );
            }
            else
            {
                break;
            }
        }

        if( xResult == CKR_FUNCTION_NOT_SUPPORTED )
        {
            break;
        }
    }

    return xResult;
}

/*-----------------------------------------------------------*/

/* Delete well-known crypto objects from storage. */
CK_RV xDestroyDefaultCryptoObjects( CK_SESSION_HANDLE xSession )
{
    CK_RV xResult;
    CK_BYTE * pxPkcsLabels[] =
    {
        ( CK_BYTE * ) pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
        ( CK_BYTE * ) pkcs11configLABEL_CODE_VERIFICATION_KEY,
        ( CK_BYTE * ) pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
        ( CK_BYTE * ) pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS
    };
    CK_OBJECT_CLASS xClass[] =
    {
        CKO_CERTIFICATE,
        CKO_PUBLIC_KEY,
        CKO_PRIVATE_KEY,
        CKO_PUBLIC_KEY
    };

    xResult = xDestroyProvidedObjects( xSession,
                                       pxPkcsLabels,
                                       xClass,
                                       sizeof( xClass ) / sizeof( CK_OBJECT_CLASS ) );

    return xResult;
}

/*-----------------------------------------------------------*/

static CK_RV prvExportPublicKey( CK_SESSION_HANDLE xSession,
                                 CK_OBJECT_HANDLE xPublicKeyHandle,
                                 uint8_t ** ppucDerPublicKey,
                                 uint32_t * pulDerPublicKeyLength )
{
    CK_RV xResult;
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_KEY_TYPE xKeyType = 0;
    CK_ATTRIBUTE xTemplate = { 0 };
    uint8_t pucEcP256AsnAndOid[] =
    {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00
    };
    uint8_t pucUnusedKeyTag[] = { 0x04, 0x41 };

    /* This variable is used only for its size. This gets rid of compiler warnings. */
    ( void ) pucUnusedKeyTag;

    xResult = C_GetFunctionList( &pxFunctionList );

    /* Query the key type. */
    if( CKR_OK == xResult )
    {
        xTemplate.type = CKA_KEY_TYPE;
        xTemplate.pValue = &xKeyType;
        xTemplate.ulValueLen = sizeof( xKeyType );
        xResult = pxFunctionList->C_GetAttributeValue( xSession,
                                                       xPublicKeyHandle,
                                                       &xTemplate,
                                                       1 );
    }

    /* Scope to ECDSA keys only, since there's currently no use case for
     * onboard keygen and certificate enrollment for RSA. */
    if( ( CKR_OK == xResult ) && ( CKK_ECDSA == xKeyType ) )
    {
        /* Query the size of the public key. */
        xTemplate.type = CKA_EC_POINT;
        xTemplate.pValue = NULL;
        xTemplate.ulValueLen = 0;
        xResult = pxFunctionList->C_GetAttributeValue( xSession,
                                                       xPublicKeyHandle,
                                                       &xTemplate,
                                                       1 );

        /* Allocate a buffer large enough for the full, encoded public key. */
        if( CKR_OK == xResult )
        {
            /* Add space for the full DER header. */
            xTemplate.ulValueLen += sizeof( pucEcP256AsnAndOid ) - sizeof( pucUnusedKeyTag );
            *pulDerPublicKeyLength = xTemplate.ulValueLen;

            /* Get a heap buffer. */
            *ppucDerPublicKey = pvPortMalloc( xTemplate.ulValueLen );

            /* Check for resource exhaustion. */
            if( NULL == *ppucDerPublicKey )
            {
                xResult = CKR_HOST_MEMORY;
            }
        }

        /* Export the public key. */
        if( CKR_OK == xResult )
        {
            xTemplate.pValue = *ppucDerPublicKey + sizeof( pucEcP256AsnAndOid ) - sizeof( pucUnusedKeyTag );
            xTemplate.ulValueLen -= ( sizeof( pucEcP256AsnAndOid ) - sizeof( pucUnusedKeyTag ) );
            xResult = pxFunctionList->C_GetAttributeValue( xSession,
                                                           xPublicKeyHandle,
                                                           &xTemplate,
                                                           1 );
        }

        /* Prepend the full DER header. */
        if( CKR_OK == xResult )
        {
            memcpy( *ppucDerPublicKey, pucEcP256AsnAndOid, sizeof( pucEcP256AsnAndOid ) );
        }
    }

    /* Free memory if there was an error after allocation. */
    if( ( NULL != *ppucDerPublicKey ) && ( CKR_OK != xResult ) )
    {
        vPortFree( *ppucDerPublicKey );
        *ppucDerPublicKey = NULL;
    }

    return xResult;
}


/*-----------------------------------------------------------*/

/* Write the ASN.1 encoded bytes of the device public key to the console.
 * This is for debugging purposes as well as to faciliate developer-driven
 * certificate enrollment for onboard crypto hardware (i.e. if available). */
static void prvWriteHexBytesToConsole( char * pcDescription,
                                       uint8_t * pucData,
                                       uint32_t ulDataLength )
{
#define BYTES_TO_DISPLAY_PER_ROW    16
    char pcByteRow[ 1 + ( BYTES_TO_DISPLAY_PER_ROW * 2 ) + ( BYTES_TO_DISPLAY_PER_ROW / 2 ) ];
    char * pcNextChar = pcByteRow;
    uint32_t ulIndex = 0;
    uint8_t ucByteValue = 0;

    /* Write help text to the console. */
    configPRINTF( ( "%s, %d bytes:\r\n", pcDescription, ulDataLength ) );

    /* Iterate over the bytes of the encoded public key. */
    for( ; ulIndex < ulDataLength; ulIndex++ )
    {
        /* Convert one byte to ASCII hex. */
        ucByteValue = *( pucData + ulIndex );
        snprintf( pcNextChar,
                  sizeof( pcByteRow ) - ( pcNextChar - pcByteRow ),
                  "%02x",
                  ucByteValue );
        pcNextChar += 2;

        /* Check for the end of a two-byte display word. */
        if( 0 == ( ( ulIndex + 1 ) % sizeof( uint16_t ) ) )
        {
            *pcNextChar = ' ';
            pcNextChar++;
        }

        /* Check for the end of a row. */
        if( 0 == ( ( ulIndex + 1 ) % BYTES_TO_DISPLAY_PER_ROW ) )
        {
            *pcNextChar = '\0';
            vLoggingPrint( pcByteRow );
            vLoggingPrint( "\r\n" );
            pcNextChar = pcByteRow;
        }
    }

    /* Check for a partial line to print. */
    if( pcNextChar > pcByteRow )
    {
        *pcNextChar = '\0';
        vLoggingPrint( pcByteRow );
        vLoggingPrint( "\r\n" );
    }
}

/*-----------------------------------------------------------*/
/*static CK_RV prvExportCertificate( CK_SESSION_HANDLE xSession, */
/*    CK_OBJECT_HANDLE xCertificateHandle, */
/*    uint8_t ** ppucDerCertificate, */
/*    uint32_t * pulDerCertificateLength ) */
/*{ */
/*    CK_RV xResult; */
/*    CK_FUNCTION_LIST_PTR pxFunctionList; */
/*    CK_ATTRIBUTE xTemplate = { 0 }; */
/* */
/* */
/*    xResult = C_GetFunctionList( &pxFunctionList ); */
/* */
/*    / * Scope to ECDSA keys only, since there's currently no use case for */
/*     * onboard keygen and certificate enrollment for RSA. * / */
/*    if ( (CKR_OK == xResult)  ) */
/*    { */
/*        / * Query the size of the certificate key. * / */
/*        xTemplate.type = CKA_VALUE; */
/*        xTemplate.pValue = NULL; */
/*        xTemplate.ulValueLen = 0; */
/*        xResult = pxFunctionList->C_GetAttributeValue( xSession, */
/*            xCertificateHandle, */
/*            &xTemplate, */
/*            1 ); */
/* */
/*        / * Allocate a buffer large enough for the full, encoded public key. * / */
/*        if ( CKR_OK == xResult ) */
/*        { */
/*            / * Add space for the full DER header. * / */
/*            xTemplate.ulValueLen += sizeof( pucEcP256AsnAndOid ) - sizeof( pucUnusedKeyTag ); */
/*            *pulDerCertificateLength = xTemplate.ulValueLen; */
/* */
/*            / * Get a heap buffer. * / */
/*            *ppucDerCertificate = pvPortMalloc( xTemplate.ulValueLen ); */
/* */
/*            / * Check for resource exhaustion. * / */
/*            if ( NULL == *ppucDerCertificate ) */
/*            { */
/*                xResult = CKR_HOST_MEMORY; */
/*            } */
/*        } */
/* */
/*        / * Export the public key. * / */
/*        if ( CKR_OK == xResult ) */
/*        { */
/*            xTemplate.pValue = *ppucDerCertificate + sizeof( pucEcP256AsnAndOid ) - sizeof( pucUnusedKeyTag ); */
/*            xTemplate.ulValueLen -= (sizeof( pucEcP256AsnAndOid ) - sizeof( pucUnusedKeyTag )); */
/*            xResult = pxFunctionList->C_GetAttributeValue( xSession, */
/*                xCertificateHandle, */
/*                &xTemplate, */
/*                1 ); */
/*        } */
/* */
/*        / * Prepend the full DER header. * / */
/*        if ( CKR_OK == xResult ) */
/*        { */
/*            memcpy( *ppucDerCertificate, pucEcP256AsnAndOid, sizeof( pucEcP256AsnAndOid ) ); */
/*        } */
/*    } */
/* */
/*    / * Free memory if there was an error after allocation. * / */
/*    if ( (NULL != *ppucDerCertificate) && (CKR_OK != xResult) ) */
/*    { */
/*        vPortFree( *ppucDerCertificate ); */
/*        *ppucDerCertificate = NULL; */
/*    } */
/* */
/*    return xResult; */
/*} */

/* Determine which required client crypto objects are already present in
 * storage. */
static CK_RV prvGetProvisionedState( CK_SESSION_HANDLE xSession,
                                     ProvisionedState_t * pxProvisionedState )
{
    CK_RV xResult;
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_SLOT_ID_PTR pxSlotId = NULL;
    CK_ULONG ulSlotCount = 0;
    CK_TOKEN_INFO xTokenInfo = { 0 };
    int i = 0;

    xResult = C_GetFunctionList( &pxFunctionList );

    /* Check for a private key. */
    if( CKR_OK == xResult )
    {
        xResult = xFindObjectWithLabelAndClass( xSession,
                                                pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                                CKO_PRIVATE_KEY,
                                                &pxProvisionedState->xPrivateKey );
    }

    if( ( CKR_OK == xResult ) && ( CK_INVALID_HANDLE != pxProvisionedState->xPrivateKey ) )
    {
        DEV_MODE_KEY_PROVISIONING_PRINT( ( "Device Private Key Exists. \r\n" ) );
        /* Check also for the corresponding public. */
        xResult = xFindObjectWithLabelAndClass( xSession,
                                                pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                                CKO_PUBLIC_KEY,
                                                &pxProvisionedState->xPublicKey );
    }

    if( ( CKR_OK == xResult ) && ( CK_INVALID_HANDLE != pxProvisionedState->xPublicKey ) )
    {
        DEV_MODE_KEY_PROVISIONING_PRINT( ( "Device Public Key Exists. \r\n" ) );
        /* Export the public key. */
        xResult = prvExportPublicKey( xSession,
                                      pxProvisionedState->xPublicKey,
                                      &pxProvisionedState->pucDerPublicKey,
                                      &pxProvisionedState->ulDerPublicKeyLength );
        prvWriteHexBytesToConsole( "Device public key",
                                   pxProvisionedState->pucDerPublicKey,
                                   pxProvisionedState->ulDerPublicKeyLength );
    }

    /* Check for the client certificate. */
    if( CKR_OK == xResult )
    {
        xResult = xFindObjectWithLabelAndClass( xSession,
                                                pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                                CKO_CERTIFICATE,
                                                &pxProvisionedState->xClientCertificate );
    }

    /* Check for a crypto element identifier. */
    if( CKR_OK == xResult )
    {
        xResult = xGetSlotList( &pxSlotId, &ulSlotCount );
    }

    if( CKR_OK == xResult )
    {
        xResult = pxFunctionList->C_GetTokenInfo( pxSlotId[ 0 ], &xTokenInfo );
    }

    if( ( CKR_OK == xResult ) && ( '\0' != xTokenInfo.label[ 0 ] ) && ( ' ' != xTokenInfo.label[ 0 ] ) )
    {
        /* PKCS #11 requires that token info fields are padded out with space
         * characters. However, a NULL terminated copy will be more useful to the
         * caller. */
        for( i = 0; i < sizeof( xTokenInfo.label ); i++ )
        {
            if( xTokenInfo.label[ i ] == ' ' )
            {
                break;
            }
        }

        if( 0 != i )
        {
            pxProvisionedState->pcIdentifier = ( char * ) pvPortMalloc( 1 + i * sizeof( xTokenInfo.label[ 0 ] ) );

            if( NULL != pxProvisionedState->pcIdentifier )
            {
                memcpy( pxProvisionedState->pcIdentifier,
                        xTokenInfo.label,
                        i );
                pxProvisionedState->pcIdentifier[ i ] = '\0';
            }
            else
            {
                xResult = CKR_HOST_MEMORY;
            }
        }
    }

    return xResult;
}

/* Attempt to provision the device with a client certificate, associated
 * private and public key pair, and optional Just-in-Time Registration certificate.
 * If either component of the key pair is unavailable in storage, generate a new
 * pair. */
CK_RV xProvisionDevice( CK_SESSION_HANDLE xSession,
                        ProvisioningParams_t * pxParams )
{
    CK_RV xResult;
    CK_FUNCTION_LIST_PTR pxFunctionList;
    ProvisionedState_t xProvisionedState = { 0 };
    CK_OBJECT_HANDLE xObject = 0;
    CK_BBOOL xImportedPrivateKey = CK_FALSE;
    CK_BBOOL xKeyPairGenerationMode = CK_FALSE;

    xResult = C_GetFunctionList( &pxFunctionList );

    #if ( pkcs11configIMPORT_PRIVATE_KEYS_SUPPORTED == 1 )

        /* Attempt to clean-up old crypto objects, but only if private key import is
         * supported by this application, and only if the caller has provided new
         * objects to use instead. */
        if( ( CKR_OK == xResult ) &&
            ( NULL != pxParams->pucClientCertificate ) &&
            ( NULL != pxParams->pucClientPrivateKey ) )
        {
            xResult = xDestroyDefaultCryptoObjects( xSession );

            if( xResult != CKR_OK )
            {
                configPRINTF( ( "Warning: could not clean-up old crypto objects. %d \r\n", xResult ) );
            }
        }
    #endif /* if ( pkcs11configIMPORT_PRIVATE_KEYS_SUPPORTED == 1 ) */

    /* If a client certificate has been provided by the caller, attempt to
     * import it. */
    if( ( xResult == CKR_OK ) && ( NULL != pxParams->pucClientCertificate ) )
    {
        xResult = xProvisionCertificate( xSession,
                                         pxParams->pucClientCertificate,
                                         pxParams->ulClientCertificateLength,
                                         ( uint8_t * ) pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                         &xObject );

        if( ( xResult != CKR_OK ) || ( xObject == CK_INVALID_HANDLE ) )
        {
            configPRINTF( ( "ERROR: Failed to provision device certificate. %d \r\n", xResult ) );
        }
    }

    #if ( pkcs11configIMPORT_PRIVATE_KEYS_SUPPORTED == 1 )

        /* If this application supports importing private keys, and if a private
         * key has been provided by the caller, attempt to import it. */
        if( ( xResult == CKR_OK ) && ( NULL != pxParams->pucClientPrivateKey ) )
        {
            xResult = xProvisionPrivateKey( xSession,
                                            pxParams->pucClientPrivateKey,
                                            pxParams->ulClientPrivateKeyLength,
                                            ( uint8_t * ) pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                            &xObject );

            if( ( xResult != CKR_OK ) || ( xObject == CK_INVALID_HANDLE ) )
            {
                configPRINTF( ( "ERROR: Failed to provision device private key with status %d.\r\n", xResult ) );
            }
            else
            {
                xImportedPrivateKey = CK_TRUE;
            }
        }
    #endif /* if ( pkcs11configIMPORT_PRIVATE_KEYS_SUPPORTED == 1 ) */

    /* If a Just-in-Time Provisioning certificate has been provided by the
     * caller, attempt to import it. Not all crypto tokens
     * and PKCS #11 module implementations provide storage for this particular
     * object. In that case, the statically defined object, if any, will be used
     * during TLS session negotiation with AWS IoT. */
    if( ( xResult == CKR_OK ) && ( NULL != pxParams->pucJITPCertificate ) )
    {
        xResult = xProvisionCertificate( xSession,
                                         pxParams->pucJITPCertificate,
                                         pxParams->ulJITPCertificateLength,
                                         ( uint8_t * ) pkcs11configLABEL_JITP_CERTIFICATE,
                                         &xObject );

        if( xResult == CKR_DEVICE_MEMORY )
        {
            xResult = CKR_OK;
            configPRINTF( ( "Warning: no persistent storage is available for the JITP certificate. The certificate in aws_clientcredential_keys.h will be used instead.\r\n" ) );
        }
    }

    /* Check whether a key pair is now present. In order to support X.509
     * certificate enrollment, the public and private key objects must both be
     * available. */
    if( ( xResult == CKR_OK ) && ( CK_FALSE == xImportedPrivateKey ) )
    {
        xResult = prvGetProvisionedState( xSession,
                                          &xProvisionedState );

        if( ( CK_INVALID_HANDLE == xProvisionedState.xPrivateKey ) ||
            ( CK_INVALID_HANDLE == xProvisionedState.xPublicKey ) ||
            ( NULL == xProvisionedState.pucDerPublicKey ) )
        {
            xKeyPairGenerationMode = CK_TRUE;
        }

        /* Ignore errors, since the board may have been previously used with a
         * different crypto middleware or app. If any of the above objects
         * couldn't be read, try to generate new ones below. */
        xResult = CKR_OK;
    }

    #if ( 1 == keyprovisioningFORCE_GENERATE_NEW_KEY_PAIR )
        xKeyPairGenerationMode = CK_TRUE;
    #endif

    if( ( xResult == CKR_OK ) && ( CK_TRUE == xKeyPairGenerationMode ) )
    {
        /* Generate a new default key pair. */
        xResult = xProvisionGenerateKeyPairEC( xSession,
                                               ( uint8_t * ) pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                               ( uint8_t * ) pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                               &xProvisionedState.xPrivateKey,
                                               &xProvisionedState.xPublicKey );

        if( CKR_OK == xResult )
        {
            /* Clean-up the previous buffer, if any. */
            if( NULL != xProvisionedState.pucDerPublicKey )
            {
                vPortFree( xProvisionedState.pucDerPublicKey );
                xProvisionedState.pucDerPublicKey = NULL;
            }

            /* Get the bytes of the new public key. */
            prvExportPublicKey( xSession,
                                xProvisionedState.xPublicKey,
                                &xProvisionedState.pucDerPublicKey,
                                &xProvisionedState.ulDerPublicKeyLength );
        }

        /* Ensure that an error condition is set if either object is still
         * missing. */
        if( ( CKR_OK == xResult ) &&
            ( ( CK_INVALID_HANDLE == xProvisionedState.xPrivateKey ) ||
              ( CK_INVALID_HANDLE == xProvisionedState.xPublicKey ) ) )
        {
            xResult = CKR_KEY_HANDLE_INVALID;
        }
    }

    /* Log the device public key for developer enrollment purposes, but only if
    * there's not already a certificate, or if a new key was just generated. */
    if( ( CKR_OK == xResult ) &&
        ( ( CK_INVALID_HANDLE == xProvisionedState.xClientCertificate ) ||
          ( CK_TRUE == xKeyPairGenerationMode ) ) &&
        ( CK_FALSE == xImportedPrivateKey ) )
    {
        configPRINTF( ( "Warning: the client certificate should be updated. Please see https://aws.amazon.com/freertos/getting-started/.\r\n" ) );

        if( NULL != xProvisionedState.pcIdentifier )
        {
            configPRINTF( ( "Recommended certificate subject name: CN=%s\r\n", xProvisionedState.pcIdentifier ) );
        }

        prvWriteHexBytesToConsole( "Device public key",
                                   xProvisionedState.pucDerPublicKey,
                                   xProvisionedState.ulDerPublicKeyLength );

        /* Delay since the downstream demo code is likely to fail quickly if
         * provisioning isn't complete, and device certificate creation in the
         * lab may depend on the developer obtaining the public key. */
        /*vTaskDelay( pdMS_TO_TICKS( 100 ) ); */
    }

    /* Free memory. */
    if( NULL != xProvisionedState.pucDerPublicKey )
    {
        vPortFree( xProvisionedState.pucDerPublicKey );
    }

    if( NULL != xProvisionedState.pcIdentifier )
    {
        vPortFree( xProvisionedState.pcIdentifier );
    }

    return xResult;
}

/*-----------------------------------------------------------*/

/* Perform device provisioning using the specified TLS client credentials. */
CK_RV vAlternateKeyProvisioning( ProvisioningParams_t * xParams )
{
    CK_RV xResult = CKR_OK;
    CK_FUNCTION_LIST_PTR pxFunctionList = NULL;
    CK_SESSION_HANDLE xSession = 0;

    xResult = C_GetFunctionList( &pxFunctionList );

    /* Initialize the PKCS Module */
    if( xResult == CKR_OK )
    {
        xResult = xInitializePkcs11Token();
    }

    if( xResult == CKR_OK )
    {
        xResult = xInitializePkcs11Session( &xSession );
    }

    if( xResult == CKR_OK )
    {
        xResult = xProvisionDevice( xSession, xParams );

        pxFunctionList->C_CloseSession( xSession );
    }

    return xResult;
}

/*-----------------------------------------------------------*/


/* Perform device provisioning using the default TLS client credentials. */
CK_RV vDevModeKeyProvisioning( void )
{
    ProvisioningParams_t xParams;

    xParams.pucJITPCertificate = ( uint8_t * ) keyJITR_DEVICE_CERTIFICATE_AUTHORITY_PEM;
    xParams.pucClientPrivateKey = ( uint8_t * ) keyCLIENT_PRIVATE_KEY_PEM;
    xParams.pucClientCertificate = ( uint8_t * ) keyCLIENT_CERTIFICATE_PEM;

    /* If using a JITR flow, a JITR certificate must be supplied. If using credentials generated by
     * AWS, this certificate is not needed. */
    if( ( NULL != xParams.pucJITPCertificate ) &&
        ( 0 != strcmp( "", ( const char * ) xParams.pucJITPCertificate ) ) )
    {
        /* We want the NULL terminator to be written to storage, so include it
         * in the length calculation. */
        xParams.ulJITPCertificateLength = sizeof( char ) + strlen( ( const char * ) xParams.pucJITPCertificate );
    }
    else
    {
        xParams.pucJITPCertificate = NULL;
    }

    /* The hard-coded client certificate and private key can be useful for
     * first-time lab testing. They are optional after the first run, though, and
     * not recommended at all for going into production. */
    if( ( NULL != xParams.pucClientPrivateKey ) &&
        ( 0 != strcmp( "", ( const char * ) xParams.pucClientPrivateKey ) ) )
    {
        /* We want the NULL terminator to be written to storage, so include it
         * in the length calculation. */
        xParams.ulClientPrivateKeyLength = sizeof( char ) + strlen( ( const char * ) xParams.pucClientPrivateKey );
    }
    else
    {
        xParams.pucClientPrivateKey = NULL;
    }

    if( ( NULL != xParams.pucClientCertificate ) &&
        ( 0 != strcmp( "", ( const char * ) xParams.pucClientCertificate ) ) )
    {
        /* We want the NULL terminator to be written to storage, so include it
         * in the length calculation. */
        xParams.ulClientCertificateLength = sizeof( char ) + strlen( ( const char * ) xParams.pucClientCertificate );
    }
    else
    {
        xParams.pucClientCertificate = NULL;
    }

    return vAlternateKeyProvisioning( &xParams );
}

/*-----------------------------------------------------------*/

//CK_SESSION_HANDLE xSession = CK_INVALID_HANDLE;
//CK_FUNCTION_LIST_PTR pxFunctionList = NULL;
//CK_OBJECT_HANDLE xPrivateKeyHandle = CK_INVALID_HANDLE;
//CK_OBJECT_HANDLE xPublicKeyHandle = CK_INVALID_HANDLE;

CK_RV vGenerateECDSAKeyPair( void )
{
    CK_RV xResult = CKR_OK;
  CK_SESSION_HANDLE xSession = CK_INVALID_HANDLE;
CK_FUNCTION_LIST_PTR pxFunctionList = NULL;
CK_OBJECT_HANDLE xPrivateKeyHandle = CK_INVALID_HANDLE;
CK_OBJECT_HANDLE xPublicKeyHandle = CK_INVALID_HANDLE;

    CK_BYTE_PTR pxPublicKeyBytes = NULL;
    size_t xPublicKeyLength = 0;

    xResult = C_GetFunctionList( &pxFunctionList );

    /* Initialize the PKCS Module */
    if( xResult == CKR_OK )
    {
        xResult = xInitializePkcs11Token();
    }

    if( xResult == CKR_OK )
    {
        xResult = xInitializePkcs11Session( &xSession );
    }

    if( xResult == CKR_OK )
    {
        /* Generate a new ECDSA key pair using curve P256. */
        xResult = xProvisionGenerateKeyPairEC( xSession,
                                               pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                               pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                               &xPrivateKeyHandle,
                                               &xPublicKeyHandle );
    }

    if( ( xResult == CKR_OK ) && ( xPrivateKeyHandle != CK_INVALID_HANDLE ) && ( xPublicKeyHandle != CK_INVALID_HANDLE ) )
    {
        /* Get the bytes of the new public key. */
        xResult = prvExportPublicKey( xSession,
                                      xPublicKeyHandle,
                                      &pxPublicKeyBytes,
                                      &xPublicKeyLength );

        if( xResult == CKR_OK )
        {
            /* Print the public key to the console. */
            prvWriteHexBytesToConsole( "\r\nDevice public key",
                                       pxPublicKeyBytes,
                                       xPublicKeyLength );

            vPortFree( pxPublicKeyBytes );
        }
    }

    if( xResult == CKR_OK )
    {
        xResult = pxFunctionList->C_CloseSession( xSession );
    }

    return xResult;
}


/* GLOBAL VARIABLES */
CK_SESSION_HANDLE xGlobalSession;
CK_RV xResult;

CK_OBJECT_HANDLE xPrivateKeyHandle = CK_INVALID_HANDLE;
CK_OBJECT_HANDLE xPublicKeyHandle = CK_INVALID_HANDLE;
CK_FUNCTION_LIST_PTR pxGlobalFunctionList;

/*-----------------------------------------------------------*/

/* Declaration of demo function. */
void vStartKeyProvisioningDemo( void );

/*-----------------------------------------------------------*/


/* @brief Random Number Generator Used to Generate CSR
 *
 *
 *	\param[in] pkcs_session     Pointer to PKCS Session Handle
 *
 *  \param[in] pucRandom        Starting Point
 *
 *  \param[in] xRandomLength    Length
 *
 *  \return 0 on success
 *
 */
static int prvRNG( void * pkcs_session,
    unsigned char * pucRandom,
    size_t xRandomLength )
{
    BaseType_t xResult;
    CK_FUNCTION_LIST_PTR pxP11FunctionList;

    xResult = C_GetFunctionList( &pxP11FunctionList );

    xResult = pxP11FunctionList->C_GenerateRandom( (*(( CK_SESSION_HANDLE * ) pkcs_session)), pucRandom, xRandomLength );

    if ( xResult != 0 )
    {
        configPRINTF( ("ERROR: Failed to generate random bytes %d \r\n", xResult) );
      
    }

    return xResult;
}

/*-----------------------------------------------------------*/

/* @brief Alternate Signing Function to be Passed into PK Context Header
 * This function was copied from "iot_tls.c"
 * Recreated to be passed into a PK Context header as our customized signing function.
 * */
static int prvPrivateKeySigningCallback( void * pvContext,
    mbedtls_md_type_t xMdAlg,
    const unsigned char * pucHash,
    size_t xHashLen,
    unsigned char * pucSig,
    size_t * pxSigLen,
    int( *piRng )(void *,
        unsigned char *,
        size_t), /*lint !e955 This parameter is unused. */
    void * pvRng )
{
    CK_RV xResult = 0;
    int lFinalResult = 0;
    CK_MECHANISM xMech = { 0 };
    CK_BYTE xToBeSigned[ 256 ];
    uint8_t ucTemp[ 64 ] = { 0 }; /* A temporary buffer for the pre-formatted signature. */
    CK_ULONG xToBeSignedLen = sizeof( xToBeSigned );


    /* Unreferenced parameters. */
    ( void ) (piRng);
    ( void ) (pvRng);
    ( void ) (xMdAlg);

    /* Sanity check buffer length. */
    if ( xHashLen > sizeof( xToBeSigned ) )
    {
        xResult = CKR_ARGUMENTS_BAD;
    }

    xMech.mechanism = CKM_ECDSA;
    memcpy( xToBeSigned, pucHash, xHashLen );
    xToBeSignedLen = xHashLen;

    if ( 0 == xResult )
    {
        /* Use the PKCS#11 module to sign. */
        xResult = pxGlobalFunctionList->C_SignInit( xGlobalSession,
            &xMech,
            xPrivateKeyHandle );
    }

    if ( 0 == xResult )
    {
        *pxSigLen = sizeof( xToBeSigned );
        xResult = pxGlobalFunctionList->C_Sign( ( CK_SESSION_HANDLE ) xGlobalSession,
            xToBeSigned,
            xToBeSignedLen,
            pucSig,
            ( CK_ULONG_PTR ) pxSigLen );
    }

    uint8_t * pucSigPtr;

    /* PKCS #11 for P256 returns a 64-byte signature with 32 bytes for R and 32 bytes for S.
     * This must be converted to an ASN1 encoded array. */
    configASSERT( *pxSigLen == 64 );
    memcpy( ucTemp, pucSig, *pxSigLen );

    pucSig[ 0 ] = 0x30; /* Sequence. */
    pucSig[ 1 ] = 0x44; /* The minimum length the signature could be. */
    pucSig[ 2 ] = 0x02; /* Integer. */

    if ( ucTemp[ 0 ] & 0x80 )
    {
        pucSig[ 1 ]++;
        pucSig[ 3 ] = 0x21;
        pucSig[ 4 ] = 0x0;
        memcpy( &pucSig[ 5 ], ucTemp, 32 );
        pucSigPtr = pucSig + 33 + 4;
    }
    else
    {
        pucSig[ 3 ] = 0x20;
        memcpy( &pucSig[ 4 ], ucTemp, 32 );
        pucSigPtr = pucSig + 32 + 4;
    }

    pucSigPtr[ 0 ] = 0x02; /* Integer. */
    pucSigPtr++;

    if ( ucTemp[ 32 ] & 0x80 )
    {
        pucSig[ 1 ]++;
        pucSigPtr[ 0 ] = 0x21;
        pucSigPtr[ 1 ] = 0x00;
        pucSigPtr += 2;

        memcpy( pucSigPtr, &ucTemp[ 32 ], 32 );
    }
    else
    {
        pucSigPtr[ 0 ] = 0x20;
        pucSigPtr++;
        memcpy( pucSigPtr, &ucTemp[ 32 ], 32 );
    }

    *pxSigLen = ( CK_ULONG ) pucSig[ 1 ] + 2;

    if ( xResult != 0 )
    {
        configPRINTF( ("ERROR: Failure in signing callback: %d \r\n", xResult) );
    }

    return lFinalResult;
}

/*-----------------------------------------------------------*/

/* @brief Provision Device Using Device and CA Certificates
 *
 *
 *	\return    Void
 *  Prints error message upon failure, success message upon success
 *
 */
static int xProvisionDeviceForJITP( void )
{
    /* Provisioning Device Certificate */
    CK_OBJECT_HANDLE xObject = 0;

    xResult = xProvisionCertificate( xGlobalSession,
        keyCLIENT_CERTIFICATE_PEM,
        sizeof( keyCLIENT_CERTIFICATE_PEM ),
        ( uint8_t * ) pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
        &xObject );

    if ( (xResult != CKR_OK) || (xObject == CK_INVALID_HANDLE) )
    {
        configPRINTF( ("ERROR: Failed to provision device certificate. %d \r\n", xResult) );
        return -1;
    }

    /* Provisioning JITR CA Certificate */
    if ( xResult == CKR_OK )
    {
        if ( sizeof( keyJITR_DEVICE_CERTIFICATE_AUTHORITY_PEM ) != 0 )
        {
            xResult = xProvisionCertificate( xGlobalSession,
                keyJITR_DEVICE_CERTIFICATE_AUTHORITY_PEM,
                sizeof( keyJITR_DEVICE_CERTIFICATE_AUTHORITY_PEM ),
                ( uint8_t * ) pkcs11configLABEL_JITP_CERTIFICATE,
                &xObject );

            xResult = CKR_OK;
        }
    }

    if ( xResult == CKR_OK )
    {
        configPRINTF( ("Device credential provisioning succeeded.\r\n") );
        return 0;
    }
    else
    {
        configPRINTF( ("ERROR: %d - Device credential provisioning failed.\r\n", xResult) );
        return -1;
    }
}

/*-----------------------------------------------------------*/

/* @brief Provisions a Device Using Internally Generated Keys
 *
 *
 *  \return Void function, console outputs upon success/failure
 *
 */
int xDeviceProvisioningForJITP( void )
{
    xResult = xInitializePkcs11Session( &xGlobalSession );

    BaseType_t xHeapBefore;
    BaseType_t xHeapAfter;

    /* xHeapBefore = xPortGetFreeHeapSize(); */
    /* configPRINTF(("Heap size before is %d", xHeapBefore)); */

    if ( xResult == CKR_OK )
    {
        xResult = C_GetFunctionList( &pxGlobalFunctionList );
    }
    else
    {
        configPRINTF( ("ERROR: %d - Failed to open PKCS #11 session.\r\n", xResult) );
    }

    if ( xResult != CKR_OK )
    {
        configPRINTF( ("ERROR: %d - Failed to get function list.\r\n", xResult) );
    }

#if ( !DEMO_PART && xResult == CKR_OK )
    {
        CK_BYTE xHashedMessage[ pkcs11SHA256_DIGEST_LENGTH ] = { 0xab };
        CK_MECHANISM xMechanism;
        CK_BYTE xSignature[ pkcs11RSA_2048_SIGNATURE_LENGTH ] = { 0 };
        CK_BYTE xEcPoint[ 256 ] = { 0 };
        CK_KEY_TYPE xKeyType;
        CK_ULONG xSignatureLength;
        CK_ATTRIBUTE xTemplate;
        CK_OBJECT_CLASS xClass;

        /* mbedTLS structures for verification. */
        int lMbedTLSResult;
        int ret;
        mbedtls_ecdsa_context xEcdsaContext;

        //xResult = xDestroyCredentials( xGlobalSession );

        if ( xResult == CKR_OK )
        {
            xResult = xProvisionGenerateKeyPairEC( xGlobalSession,
                ( uint8_t * ) pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                ( uint8_t * ) pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                &xPrivateKeyHandle,
                &xPublicKeyHandle );
        }
        else
        {
            configPRINTF( ("ERROR: %d - Failed to destroy credentials before Generating Key Pair.\r\n", xResult) );
        }

        if ( xPrivateKeyHandle == CK_INVALID_HANDLE )
        {
            configPRINTF( ("ERROR: %d - Invalid private key handle generated by GenerateKeyPair.\r\n", xPrivateKeyHandle) );
        }

        if ( xPublicKeyHandle == CK_INVALID_HANDLE )
        {
            configPRINTF( ("ERROR: %d - Invalid public key handle generated by GenerateKeyPair.\r\n", xPublicKeyHandle) );
        }

        /* Call GetAttributeValue to retrieve information about the keypair stored. */
        /* Check that correct object class retrieved. */
        xTemplate.type = CKA_CLASS;
        xTemplate.pValue = NULL;
        xTemplate.ulValueLen = 0;

        if ( xResult == CKR_OK )
        {
            xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKeyHandle, &xTemplate, 1 );
        }
        else
        {
            configPRINTF( ("ERROR: %d - Generating EC key pair failed.", xResult) );
        }

        if ( xTemplate.ulValueLen != sizeof( CK_OBJECT_CLASS ) )
        {
            configPRINTF( ("Incorrect object class length returned from GetAttributeValue.\r\n") );
        }

        xTemplate.pValue = &xClass;

        if ( xResult == CKR_OK )
        {
            xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKeyHandle, &xTemplate, 1 );
        }
        else
        {
            configPRINTF( ("ERROR: %d - GetAttributeValue for length of public EC key class failed.\r\n", xResult) );
        }

        if ( xClass != CKO_PRIVATE_KEY )
        {
            configPRINTF( ("ERROR: %d - Incorrect object class returned from GetAttributeValue.\r\n", xClass) );
        }

        xTemplate.pValue = &xClass;

        if ( xResult == CKR_OK )
        {
            xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKeyHandle, &xTemplate, 1 );
        }
        else
        {
            configPRINTF( ("ERROR: %d - GetAttributeValue for private EC key class failed.\r\n", xResult) );
        }

        if ( xClass != CKO_PUBLIC_KEY )
        {
            configPRINTF( ("ERROR: %d - Incorrect object class returned from GetAttributeValue.\r\n", xClass) );
        }

        /* Check that both keys are stored as EC Keys. */
        xTemplate.type = CKA_KEY_TYPE;
        xTemplate.pValue = &xKeyType;
        xTemplate.ulValueLen = sizeof( CK_KEY_TYPE );

        if ( xResult == CKR_OK )
        {
            xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKeyHandle, &xTemplate, 1 );
        }
        else
        {
            configPRINTF( ("ERROR: %d - GetAttributeValue for public EC key class failed.\r\n", xResult) );
        }

        if ( xTemplate.ulValueLen != sizeof( CK_KEY_TYPE ) )
        {
            configPRINTF( ("Length of key type incorrect in GetAttributeValue.\r\n") );
        }

        if ( xKeyType != CKK_EC )
        {
            configPRINTF( ("ERROR: %d - Incorrect key type for private key.\r\n", xKeyType) );
        }

        if ( xResult == CKR_OK )
        {
            xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKeyHandle, &xTemplate, 1 );
        }
        else
        {
            configPRINTF( ("ERROR: %d - Error getting attribute value of EC key type.\r\n", xResult) );
        }

        if ( xTemplate.ulValueLen != sizeof( CK_KEY_TYPE ) )
        {
            configPRINTF( ("Length of key type incorrect in GetAttributeValue.\r\n") );
        }

        if ( xKeyType != CKK_EC )
        {
            configPRINTF( ("ERROR: %d - Incorrect key type for public key.\r\n", xKeyType) );
        }

        /* Check that public key point can be retrieved for public key. */
        xTemplate.type = CKA_EC_POINT;
        xTemplate.pValue = xEcPoint;
        xTemplate.ulValueLen = sizeof( xEcPoint );

        if ( xResult == CKR_OK )
        {
            xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKeyHandle, &xTemplate, 1 );
        }
        else
        {
            configPRINTF( ("ERROR: %d - Error getting attribute value of EC key type.\r\n", xResult) );
        }

        /* Perform a sign with the generated private key. */
        xMechanism.mechanism = CKM_ECDSA;
        xMechanism.pParameter = NULL;
        xMechanism.ulParameterLen = 0;

        if ( xResult == CKR_OK )
        {
            xResult = pxGlobalFunctionList->C_SignInit( xGlobalSession, &xMechanism, xPrivateKeyHandle );
        }
        else
        {
            configPRINTF( ("ERROR: %d - Failed to retrieve EC Point.\r\n", xResult) );
        }

        xSignatureLength = sizeof( xSignature );

        if ( xResult == CKR_OK )
        {
            xResult = pxGlobalFunctionList->C_Sign( xGlobalSession, xHashedMessage, pkcs11SHA256_DIGEST_LENGTH, xSignature, &xSignatureLength );
        }
        else
        {
            configPRINTF( ("ERROR: %d - Failed to SignInit ECDSA.\r\n", xResult) );
        }

        if ( xResult != CKR_OK )
        {
            configPRINTF( ("ERROR: %d - Failed to ECDSA Sign.\r\n", xResult) );
        }

        /* Verify the signature with mbedTLS */
        mbedtls_ecdsa_init( &xEcdsaContext );
        mbedtls_ecp_group_init( &xEcdsaContext.grp );


        /*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////// */
        mbedtls_mpi xR;
        mbedtls_mpi xS;

        lMbedTLSResult = mbedtls_ecp_group_load( &xEcdsaContext.grp, MBEDTLS_ECP_DP_SECP256R1 );

        if ( lMbedTLSResult == 0 )
        {
            /* The first 2 bytes are for ASN1 type/length encoding. */
            lMbedTLSResult = mbedtls_ecp_point_read_binary( &xEcdsaContext.grp, &xEcdsaContext.Q, &xEcPoint[ 2 ], xTemplate.ulValueLen - 2 );
        }
        else
        {
            configPRINTF( ("ERROR: %d - mbedTLS failed in setup for signature verification.\r\n", lMbedTLSResult) );
        }

        /* C_Sign returns the R & S components one after another- import these into a format that mbedTLS can work with. */
        mbedtls_mpi_init( &xR );
        mbedtls_mpi_init( &xS );

        if ( lMbedTLSResult == 0 )
        {
            lMbedTLSResult = mbedtls_mpi_read_binary( &xR, &xSignature[ 0 ], 32 );
        }
        else
        {
            configPRINTF( ("ERROR: %d - mbedTLS failed in setup for signature verification.\r\n", lMbedTLSResult) );
        }

        if ( lMbedTLSResult == 0 )
        {
            lMbedTLSResult = mbedtls_mpi_read_binary( &xS, &xSignature[ 32 ], 32 );
        }
        else
        {
            configPRINTF( ("ERROR: %d - mbedTLS failed in setup for signature verification.\r\n", lMbedTLSResult) );
        }

        if ( lMbedTLSResult == 0 )
        {
            /* Verify using mbedTLS & exported public key. */
            lMbedTLSResult = mbedtls_ecdsa_verify( &xEcdsaContext.grp, xHashedMessage, sizeof( xHashedMessage ), &xEcdsaContext.Q, &xR, &xS );
        }
        else
        {
            configPRINTF( ("ERROR: %d - mbedTLS failed in setup for signature verification.\r\n", lMbedTLSResult) );
        }

        if ( lMbedTLSResult != 0 )
        {
            configPRINTF( ("ERROR: %d - mbedTLS failed to verify signature.\r\n", lMbedTLSResult) );
        }

        /* Verify the signature with the generated public key. */
        xResult = pxGlobalFunctionList->C_VerifyInit( xGlobalSession, &xMechanism, xPublicKeyHandle );

        if ( xResult == CKR_OK )
        {
            xResult = pxGlobalFunctionList->C_Verify( xGlobalSession, xHashedMessage, pkcs11SHA256_DIGEST_LENGTH, xSignature, xSignatureLength );
        }
        else
        {
            configPRINTF( ("ERROR: %d - Failed to VerifyInit ECDSA.\r\n", xResult) );
        }

        if ( xResult != CKR_OK )
        {
            configPRINTF( ("ERROR: %d - Failed to Verify ECDSA.\r\n", xResult) );
        }

        mbedtls_mpi_free( &xR );
        mbedtls_mpi_free( &xS );

        /*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////// */


        /* Generate a PK Context for CSR */
        /* Getting header info from ECKEY type */
        mbedtls_pk_type_t type_key = MBEDTLS_PK_ECKEY;
        const mbedtls_pk_info_t * header = mbedtls_pk_info_from_type( type_key );

        /* Creating copy of header to pass in custom sign function (original header is immutable) */
        mbedtls_pk_info_t * header_copy = pvPortMalloc( sizeof( mbedtls_pk_info_t ) );

        if ( header_copy == NULL )
        {
            configPRINTF( ("ERROR: Failed to allocate memory for header_copy variable. CSR cannot be generated\r\n") );
            return;
        }

        memcpy( header_copy, header, sizeof( struct mbedtls_pk_info_t ) );

        header_copy->sign_func = &prvPrivateKeySigningCallback;

        /* Initializing PK Context */
        mbedtls_pk_context pk_cont;
        mbedtls_pk_init( &pk_cont );
        ret = mbedtls_pk_setup( &pk_cont, header_copy );

        pk_cont.pk_ctx = &xEcdsaContext;


        /* Generating CSR */
        /* Initializing CSR Context */
        mbedtls_x509write_csr my_csr;
        mbedtls_x509write_csr_init( &my_csr );

        if ( ret == 0 )
        {
            ret = mbedtls_x509write_csr_set_subject_name( &my_csr, "CN=ThingName" ); /* This name is configurable to your personal thing name. */
        }
        else
        {
            configPRINTF( ("ERROR: %d - Failed to initialize PK context with given information.\r\n", ret) );
        }

        mbedtls_x509write_csr_set_key( &my_csr, &pk_cont );
        mbedtls_x509write_csr_set_md_alg( &my_csr, MBEDTLS_MD_SHA256 );

        if ( ret == 0 )
        {
            ret = mbedtls_x509write_csr_set_key_usage( &my_csr, MBEDTLS_X509_KU_DIGITAL_SIGNATURE );
        }
        else
        {
            configPRINTF( ("ERROR: %d - Failed to set subject name of CSR context.\r\n", ret) );
        }

        if ( ret == 0 )
        {
            ret = mbedtls_x509write_csr_set_ns_cert_type( &my_csr, MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT );
        }
        else
        {
            configPRINTF( ("ERROR: %d - Failed to set key usage of CSR context.\r\n", ret) );
        }

        /* Output Buffer */
        unsigned char * final_csr = pvPortMalloc( 2000 );

        if ( final_csr == NULL )
        {
            configPRINTF( ("ERROR: Failed to allocate memory for final_csr variable. CSR cannot be generated\r\n") );
            return;
        }

        size_t len_buf = ( size_t ) 2000;

        if ( ret == 0 )
        {
            ret = mbedtls_x509write_csr_pem( &my_csr, final_csr, len_buf, &prvRNG, &xGlobalSession );
        }
        else
        {
            configPRINTF( ("ERROR: %d - Failed to set NS Cert Type of CSR context.\r\n", ret) );
        }

        if ( ret != 0 )
        {
            configPRINTF( ("ERROR: %d - Failed to write CSR.\r\n", ret) );
        }

        /* Console Outputs */
        unsigned char * csr_message = "Copy the following Certificate Signing Request into tools/reinvent_demo/device.csr :";
        unsigned char * script_message = "2) ONCE YOU'VE COPIED THE CERTIFICATE REQUEST, PLEASE RUN THE SCRIPT NAMED\n\t\t\"device_cert.h\" LOCATED IN tools/create_certs";
        unsigned char * cert_message = "3) ONCE YOU HAVE COMPLETED RUNNING THE SCRIPT, OPEN \"aws_clientcrediental_keys.h\" AND:"                                                                  \
            "\n\ta) FORMAT THE TWO CERTIFICATES LOCATED IN tools/create_certs/deviceCertAndCACert.crt\n\t\tUSING tools/certificate_configuration/PEMfileToCString.html" \
            "\n\tb) PASTE THE RESULTING TWO C STRINGS INTO\n\t\tkeyCLIENT_CERTIFICATE_PEM AND keyJITR_DEVICE_CERTIFICATE_AUTHORITY_PEM, RESPECTIVELY,\n\t\tIN \"aws_clientcrediental_keys.h\"";

        configPRINTF( ("\n\n%s\n\n%s\n", csr_message, final_csr) );

        /* Freeing Memory */
        mbedtls_ecp_group_free( &xEcdsaContext.grp );
        mbedtls_ecdsa_free( &xEcdsaContext );
        /*mbedtls_pk_free( &pk_cont ); */
        /*header_copy->ctx_free_func( &pk_cont ); */
        mbedtls_x509write_csr_free( &my_csr );
        vPortFree( final_csr );

        /* xHeapAfter = xPortGetFreeHeapSize(); */
        /* configPRINTF(("Heap size before is %d", xHeapAfter)); */
        while ( 1 );

        return(xResult || lMbedTLSResult || ret);


    }
#else /* if ( !DEMO_PART ) */
    {
        /* Provision device using certificates in aws_clientcredential_keys.h */
        int ret = xProvisionDeviceForJITP();

        if ( ret != 0 )
        {
            configPRINTF( ("ERROR: %d - Provisioning Function Failed.\r\n", ret) );
        }
    }
#endif /* if ( !DEMO_PART ) */
}

///* @brief Random Number Generator Used to Generate CSR
// *
// *
// *	\param[in] pkcs_session     Pointer to PKCS Session Handle
// *
// *  \param[in] pucRandom        Starting Point
// *
// *  \param[in] xRandomLength    Length
// *
// *  \return 0 on success
// *
// */
//static int prvRNG( void * pkcs_session,
//                   unsigned char * pucRandom,
//                   size_t xRandomLength )
//{
//    BaseType_t xResult;
//
//
//    xResult = pxFunctionList->C_GenerateRandom( xSession, pucRandom, xRandomLength );
//
//    if( xResult != 0 )
//    {
//        configPRINTF( ( "ERROR: Failed to generate random bytes %d \r\n", xResult ) );
//    }
//
//    return xResult;
//}
//
///*-----------------------------------------------------------*/
//
///* @brief Alternate Signing Function to be Passed into PK Context Header
// * This function was copied from "iot_tls.c"
// * Recreated to be passed into a PK Context header as our customized signing function.
// * */
//static int prvPrivateKeySigningCallback( void * pvContext,
//                                         mbedtls_md_type_t xMdAlg,
//                                         const unsigned char * pucHash,
//                                         size_t xHashLen,
//                                         unsigned char * pucSig,
//                                         size_t * pxSigLen,
//                                         int ( * piRng )( void *,
//                                                          unsigned char *,
//                                                          size_t ), /*lint !e955 This parameter is unused. */
//                                         void * pvRng )
//{
//    CK_RV xResult = 0;
//    int lFinalResult = 0;
//    CK_MECHANISM xMech = { 0 };
//    CK_BYTE xToBeSigned[ 256 ];
//    uint8_t ucTemp[ 64 ] = { 0 }; /* A temporary buffer for the pre-formatted signature. */
//    CK_ULONG xToBeSignedLen = sizeof( xToBeSigned );
//
//    /* Unreferenced parameters. */
//    ( void ) ( piRng );
//    ( void ) ( pvRng );
//    ( void ) ( xMdAlg );
//
//    /* Sanity check buffer length. */
//    if( xHashLen > sizeof( xToBeSigned ) )
//    {
//        xResult = CKR_ARGUMENTS_BAD;
//    }
//
//    xMech.mechanism = CKM_ECDSA;
//    memcpy( xToBeSigned, pucHash, xHashLen );
//    xToBeSignedLen = xHashLen;
//
//    if( 0 == xResult )
//    {
//        /* Use the PKCS#11 module to sign. */
//        xResult = pxFunctionList->C_SignInit( xSession,
//                                              &xMech,
//                                              xPrivateKeyHandle );
//    }
//
//    if( 0 == xResult )
//    {
//        *pxSigLen = sizeof( xToBeSigned );
//        xResult = pxFunctionList->C_Sign( xSession,
//                                          xToBeSigned,
//                                          xToBeSignedLen,
//                                          pucSig,
//                                          ( CK_ULONG_PTR ) pxSigLen );
//    }
//
//    uint8_t * pucSigPtr;
//
//    /* PKCS #11 for P256 returns a 64-byte signature with 32 bytes for R and 32 bytes for S.
//     * This must be converted to an ASN1 encoded array. */
//    configASSERT( *pxSigLen == 64 );
//    memcpy( ucTemp, pucSig, *pxSigLen );
//
//    pucSig[ 0 ] = 0x30; /* Sequence. */
//    pucSig[ 1 ] = 0x44; /* The minimum length the signature could be. */
//    pucSig[ 2 ] = 0x02; /* Integer. */
//
//    if( ucTemp[ 0 ] & 0x80 )
//    {
//        pucSig[ 1 ]++;
//        pucSig[ 3 ] = 0x21;
//        pucSig[ 4 ] = 0x0;
//        memcpy( &pucSig[ 5 ], ucTemp, 32 );
//        pucSigPtr = pucSig + 33 + 4;
//    }
//    else
//    {
//        pucSig[ 3 ] = 0x20;
//        memcpy( &pucSig[ 4 ], ucTemp, 32 );
//        pucSigPtr = pucSig + 32 + 4;
//    }
//
//    pucSigPtr[ 0 ] = 0x02; /* Integer. */
//    pucSigPtr++;
//
//    if( ucTemp[ 32 ] & 0x80 )
//    {
//        pucSig[ 1 ]++;
//        pucSigPtr[ 0 ] = 0x21;
//        pucSigPtr[ 1 ] = 0x00;
//        pucSigPtr += 2;
//
//        memcpy( pucSigPtr, &ucTemp[ 32 ], 32 );
//    }
//    else
//    {
//        pucSigPtr[ 0 ] = 0x20;
//        pucSigPtr++;
//        memcpy( pucSigPtr, &ucTemp[ 32 ], 32 );
//    }
//
//    *pxSigLen = ( CK_ULONG ) pucSig[ 1 ] + 2;
//
//    if( xResult != 0 )
//    {
//        configPRINTF( ( "ERROR: Failure in signing callback: %d \r\n", xResult ) );
//    }
//
//    return lFinalResult;
//}
//
//
//
//
//
//  void xGenerateCSR( void )
////{
//    /* Generate a PK Context for CSR */
//    /* Getting header info from ECKEY type */
//    mbedtls_pk_type_t type_key = MBEDTLS_PK_ECKEY;
//    const mbedtls_pk_info_t * header = mbedtls_pk_info_from_type( type_key );
//    int ret = 0;
//    mbedtls_ecdsa_context xEcdsaContext;
//
//    /* Creating copy of header to pass in custom sign function (original header is immutable) */
//    mbedtls_pk_info_t * header_copy = pvPortMalloc( sizeof( mbedtls_pk_info_t ) );
//
//    if( header_copy == NULL )
//    {
//        configPRINTF( ( "ERROR: Failed to allocate memory for header_copy variable. CSR cannot be generated\r\n" ) );
//        return;
//    }
//
//    memcpy( header_copy, header, sizeof( struct mbedtls_pk_info_t ) );
//
//    header_copy->sign_func = &prvPrivateKeySigningCallback;
//
//    /* Initializing PK Context */
//    mbedtls_pk_context pk_cont;
//    mbedtls_pk_init( &pk_cont );
//    ret = mbedtls_pk_setup( &pk_cont, header_copy );
//
//    mbedtls_mpi xR;
//    mbedtls_mpi xS;
//
//    lMbedTLSResult = mbedtls_ecp_group_load( &xEcdsaContext.grp, MBEDTLS_ECP_DP_SECP256R1 );
//
//    if ( lMbedTLSResult == 0 )
//    {
//        /* The first 2 bytes are for ASN1 type/length encoding. */
//        lMbedTLSResult = mbedtls_ecp_point_read_binary( &xEcdsaContext.grp, &xEcdsaContext.Q, &xEcPoint[ 2 ], xTemplate.ulValueLen - 2 );
//    }
//    else
//    {
//        configPRINTF( ("ERROR: %d - mbedTLS failed in setup for signature verification.\r\n", lMbedTLSResult) );
//    }
//
//
//
//    pk_cont.pk_ctx = &xEcdsaContext;
//
//
//    /* Generating CSR */
//    /* Initializing CSR Context */
//    mbedtls_x509write_csr my_csr;
//    mbedtls_x509write_csr_init( &my_csr );
//
//    if( ret == 0 )
//    {
//        ret = mbedtls_x509write_csr_set_subject_name( &my_csr, "CN=ThingName" ); /* This name is configurable to your personal thing name. */
//    }
//    else
//    {
//        configPRINTF( ( "ERROR: %d - Failed to initialize PK context with given information.\r\n", ret ) );
//    }
//
//    mbedtls_x509write_csr_set_key( &my_csr, &pk_cont );
//    mbedtls_x509write_csr_set_md_alg( &my_csr, MBEDTLS_MD_SHA256 );
//
//    if( ret == 0 )
//    {
//        ret = mbedtls_x509write_csr_set_key_usage( &my_csr, MBEDTLS_X509_KU_DIGITAL_SIGNATURE );
//    }
//    else
//    {
//        configPRINTF( ( "ERROR: %d - Failed to set subject name of CSR context.\r\n", ret ) );
//    }
//
//    if( ret == 0 )
//    {
//        ret = mbedtls_x509write_csr_set_ns_cert_type( &my_csr, MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT );
//    }
//    else
//    {
//        configPRINTF( ( "ERROR: %d - Failed to set key usage of CSR context.\r\n", ret ) );
//    }
//
//    /* Output Buffer */
//    unsigned char * final_csr = pvPortMalloc( 2000 );
//
//    if( final_csr == NULL )
//    {
//        configPRINTF( ( "ERROR: Failed to allocate memory for final_csr variable. CSR cannot be generated\r\n" ) );
//        return;
//    }
//
//    size_t len_buf = ( size_t ) 2000;
//
//    if( ret == 0 )
//    {
//        ret = mbedtls_x509write_csr_pem( &my_csr, final_csr, len_buf, &prvRNG, &xSession );
//    }
//    else
//    {
//        configPRINTF( ( "ERROR: %d - Failed to set NS Cert Type of CSR context.\r\n", ret ) );
//    }
//
//    if( ret != 0 )
//    {
//        configPRINTF( ( "ERROR: %d - Failed to write CSR.\r\n", ret ) );
//    }
//
//    configPRINTF( ("CSR Generated: \r\n %s", final_csr) );
//
//    /* Freeing Memory */
//    mbedtls_ecp_group_free( &xEcdsaContext.grp );
//    mbedtls_ecdsa_free( &xEcdsaContext );
//    /*mbedtls_pk_free( &pk_cont ); */
//    /*header_copy->ctx_free_func( &pk_cont ); */
//    mbedtls_x509write_csr_free( &my_csr );
//    vPortFree( final_csr );
//}
//
