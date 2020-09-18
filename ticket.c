#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <libgen.h>
#include "ticket.h"
#include "ticket_files.h"
#include "aes.h"

void ticket_create_cert(hp_settings_t *settings)
{
    filepath_t cert_path;
    filepath_init(&cert_path);
    filepath_copy(&cert_path, &settings->out_dir);
    filepath_append(&cert_path, "%016" PRIx64 "%016" PRIx8 ".cert", settings->title_id, (uint8_t)settings->keygeneration);
    printf("Creating cert %s\n", cert_path.char_path);
    FILE *file;
    if (!(file = os_fopen(cert_path.os_path, OS_MODE_WRITE)))
    {
        fprintf(stderr, "Error: unable to create cert\n");
        exit(EXIT_FAILURE);
    }
    fwrite(ticket_files_cert, 1, TICKETCERTSIZE, file);
    fclose(file);
}

void ticket_create_tik(hp_settings_t *settings)
{
    filepath_t tik_path;
    filepath_init(&tik_path);
    filepath_copy(&tik_path, &settings->out_dir);
    filepath_append(&tik_path, "%016" PRIx64 "%016" PRIx8 ".tik", settings->title_id, (uint8_t)settings->keygeneration);

    // Encrypting title key
    printf("Encrypting Titlekey\n");
    unsigned char enc_key[0x10];
    aes_ctx_t *aes_tkey_ctx = new_aes_ctx(settings->keyset.titlekeks[settings->keygeneration - 1], 16, AES_MODE_ECB);
    aes_encrypt(aes_tkey_ctx, enc_key, settings->title_key, 0x10);
    free_aes_ctx(aes_tkey_ctx);

    printf("Creating tik %s\n", tik_path.char_path);
    FILE *file;
    if (!(file = os_fopen(tik_path.os_path, OS_MODE_WRITE)))
    {
        fprintf(stderr, "Error: unable to create tik\n");
        exit(EXIT_FAILURE);
    }
    fwrite(ticket_files_tik, 1, TICKETTIKSIZE, file);
    fseeko64(file, 0x180, SEEK_SET);
    fwrite(enc_key, 1, 0x10, file);
    fseeko64(file, 0x285, SEEK_SET);
    fwrite((uint8_t*)&settings->keygeneration, 1, 1, file);
    fseeko64(file, 0x2A0, SEEK_SET);

    // Calculate RightsID
    uint8_t rights_id[0x10] = { 0 };
    for (int ridc = 0; ridc < 8; ridc++)
    {
        rights_id[7 - ridc] = (settings->title_id >> (8 * ridc) & 0xff);
    }
    rights_id[15] = (uint8_t)settings->keygeneration;
    
    fwrite(rights_id, 1, 0x10, file);
    
    fclose(file);
}