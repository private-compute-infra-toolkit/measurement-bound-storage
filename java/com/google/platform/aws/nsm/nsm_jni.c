/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <jni.h>
#include <stdint.h>

static const int32_t SUCCESS = 0;
static const int32_t JNI_OBJECT_ALLOCATION_ERROR = -2;

JNIEXPORT jint JNICALL Java_com_google_platform_aws_nsm_NitroSecurityModule_init(JNIEnv *env, jclass ignored)
{
    return nsm_lib_init();
}

JNIEXPORT void JNICALL Java_com_google_platform_aws_nsm_NitroSecurityModule_exit(JNIEnv *env, jclass ignored, jint fd)
{
    nsm_lib_exit(fd);
}

JNIEXPORT jobject JNICALL Java_com_google_platform_aws_nsm_NitroSecurityModule_getAttestationDoc(
    JNIEnv *env, jclass ignored, jint fd, jbyteArray user_data_array, jbyteArray nonce_array, jbyteArray public_key_array)
{
    jclass nsm_result_class = (*env)->FindClass(env, "com/google/platform/aws/nsm/NsmJniResult");
    if (nsm_result_class == NULL)
    {
        return NULL; // Should throw an exception in Java
    }
    jmethodID nsm_result_constructor_success = (*env)->GetMethodID(env, nsm_result_class, "<init>", "([B)V");
    if (nsm_result_constructor_success == NULL)
    {
        return NULL;
    }
    jmethodID nsm_result_constructor_error = (*env)->GetMethodID(env, nsm_result_class, "<init>", "(I)V");
    if (nsm_result_constructor_error == NULL)
    {
        return NULL;
    }

    static const size_t MAX_ATTESTATION_DOC_SIZE = 256 * 1024;
    uint8_t *attestation_doc = calloc(MAX_ATTESTATION_DOC_SIZE, sizeof(uint8_t));
    if (attestation_doc == NULL)
    {
        return (*env)->NewObject(env, nsm_result_class, nsm_result_constructor_error, JNI_OBJECT_ALLOCATION_ERROR);
    }

    const uint8_t *user_data = NULL;
    uint32_t user_data_len = 0;
    if (user_data_array != NULL)
    {
        user_data = (const uint8_t *)(*env)->GetByteArrayElements(env, user_data_array, NULL);
        user_data_len = (*env)->GetArrayLength(env, user_data_array);
    }

    const uint8_t *nonce = NULL;
    uint32_t nonce_len = 0;
    if (nonce_array != NULL)
    {
        nonce = (const uint8_t *)(*env)->GetByteArrayElements(env, nonce_array, NULL);
        nonce_len = (*env)->GetArrayLength(env, nonce_array);
    }

    const uint8_t *public_key = NULL;
    uint32_t public_key_len = 0;
    if (public_key_array != NULL)
    {
        public_key = (const uint8_t *)(*env)->GetByteArrayElements(env, public_key_array, NULL);
        public_key_len = (*env)->GetArrayLength(env, public_key_array);
    }

    uint32_t attestation_doc_len = MAX_ATTESTATION_DOC_SIZE;

    int result = nsm_get_attestation_doc(
        fd,
        user_data, user_data_len,
        nonce, nonce_len,
        public_key, public_key_len,
        attestation_doc, &attestation_doc_len);

    if (user_data_array != NULL)
    {
        (*env)->ReleaseByteArrayElements(env, user_data_array, (jbyte *)user_data, JNI_ABORT);
    }
    if (nonce_array != NULL)
    {
        (*env)->ReleaseByteArrayElements(env, nonce_array, (jbyte *)nonce, JNI_ABORT);
    }
    if (public_key_array != NULL)
    {
        (*env)->ReleaseByteArrayElements(env, public_key_array, (jbyte *)public_key, JNI_ABORT);
    }
    if (result == SUCCESS)
    {
        jbyteArray output_array = (*env)->NewByteArray(env, attestation_doc_len);
        if (output_array != NULL)
        {
            (*env)->SetByteArrayRegion(env, output_array, 0, attestation_doc_len, (jbyte *)attestation_doc);
            free(attestation_doc);
            return (*env)->NewObject(env, nsm_result_class, nsm_result_constructor_success, output_array);
        }
        else
        {
            free(attestation_doc);
            return (*env)->NewObject(env, nsm_result_class, nsm_result_constructor_error, JNI_OBJECT_ALLOCATION_ERROR);
        }
    }
    free(attestation_doc);
    return (*env)->NewObject(env, nsm_result_class, nsm_result_constructor_error, result);
}
