#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nca.h"
#include "utils.h"
#include "settings.h"
#include "pki.h"
#include "extkeys.h"
#include "version.h"
#include "nacp.h"
#include "npdm.h"
#include "pfs0.h"

/* hacPack by The-4n */

// Print Usage
static void usage(void)
{
    fprintf(stderr,
            "Usage: %s [options...]\n\n"
            "Options:\n"
            "General options:\n"
            "-o, --outdir             Set output directory\n"
            "-k, --keyset             Set keyset filepath, default filepath is ." OS_PATH_SEPARATOR "keys.dat\n"
            "-h, --help               Display usage\n"
            "--type                   Set file type [nca, nsp]\n"
            "--titleid                Set titleid\n"
            "NCA required options:\n"
            "--ncatype                Set nca type if file type is nca [program, control, manual, data, publicdata, meta]\n"
            "NCA general options:\n"
            "--tempdir                Set temp directory filepath, default filepath is ." OS_PATH_SEPARATOR "hacbpack_temp" OS_PATH_SEPARATOR "\n"
            "--backupdir              Set backup directory filepath, default filepath is ." OS_PATH_SEPARATOR "hacbpack_backup" OS_PATH_SEPARATOR "\n"
            "--keygeneration          Set keygeneration for encrypting key area, default keygeneration is 1\n"
            "--plaintext              Skip encrypting sections and set section header block crypto type to plaintext\n"
            "--sdkversion             Set SDK version in hex, default SDK version is 000C1100\n"
            "--keyareakey             Set key area key 2 in hex with 16 bytes length\n"
            "--ncasig                 Set nca signature type [zero, static, random]. Default is zero\n"
            "--disttype               Set nca distribution type [download, gamecard]. Default is download\n"
            "--ncasig1privatekey      Set private key filepath for signing nca signature 1 with PEM format\n"
            "Program NCA options:\n"
            "--exefsdir               Set program exefs directory path\n"
            "--romfsdir               Set program romfs directory path\n"
            "--logodir                Set program logo directory path\n"
            "--titlekey               Set Titlekey for encrypting nca\n"
            "--acidsigprivatekey      Set private key filepath for signing acid with PEM format\n"
            "--ncasig2privatekey      Set private key filepath for signing nca signature 2 with PEM format\n"
            "--ncasig2modulus         Set modulus filepath for signing nca signature 2\n"
            "--noselfsignncasig2      Skip patching acid public key in npdm and signing nca header with self-signed keys\n"
            "Control NCA options:\n"
            "--romfsdir               Set control romfs directory path\n"
            "Manual NCA options:\n"
            "--romfsdir               Set manual romfs directory path\n"
            "--titlekey               Set Titlekey for encrypting nca\n"
            "Data NCA options:\n"
            "--romfsdir               Set data romfs directory path\n"
            "PublicData NCA options:\n"
            "--romfsdir               Set publicdata romfs directory path\n"
            "--titlekey               Set Titlekey for encrypting nca\n"
            "Metadata NCA options:\n"
            "--titletype              Set cnmt title type [application, patch, addon, systemprogram, systemdata]\n"
            "--titleversion           Set title-version in hex with 4 bytes length, default value is 0x0\n"
            "--programnca             Set program nca path\n"
            "--controlnca             Set control nca path\n"
            "--legalnca               Set legal information nca path\n"
            "--htmldocnca             Set offline manual nca path\n"
            "--datanca                Set data nca path\n"
            "--cnmt                   Set cnmt path\n"
            "--digest                 Set cnmt digest\n"
            "NSP options:\n"
            "--ncadir                 Set input nca directory path\n",
            USAGE_PROGRAM_NAME);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    hp_settings_t settings;
    memset(&settings, 0, sizeof(settings));

    printf("hacPack %s by The-4n\n\n", HACPACK_VERSION);

    filepath_init(&settings.out_dir);
    filepath_init(&settings.exefs_dir);
    filepath_init(&settings.romfs_dir);
    filepath_init(&settings.logo_dir);
    filepath_init(&settings.programnca);
    filepath_init(&settings.controlnca);
    filepath_init(&settings.legalnca);
    filepath_init(&settings.htmldocnca);
    filepath_init(&settings.datanca);
    filepath_init(&settings.publicdatanca);
    filepath_init(&settings.metanca);
    filepath_init(&settings.ncadir);
    filepath_init(&settings.cnmt);
    filepath_init(&settings.acid_sig_private_key);
    filepath_init(&settings.nca_sig1_private_key);
    filepath_init(&settings.nca_sig2_private_key);
    filepath_init(&settings.nca_sig2_modulus);

    // Hardcode default temp directory
    filepath_init(&settings.temp_dir);
    filepath_set(&settings.temp_dir, "hacpack_temp");

    // Hardcode default backup directory
    filepath_init(&settings.backup_dir);
    filepath_set(&settings.backup_dir, "hacpack_backup");

    // Keyset
    filepath_t keypath;
    filepath_init(&keypath);
    pki_initialize_keyset(&settings.keyset);

    // Default Settings
    settings.keygeneration = 1;
    settings.sdk_version = 0x000C1100;
    settings.keyareakey = (unsigned char *)calloc(1, 0x10);
    memset(settings.keyareakey, 4, 0x10);

    // Parse options
    while (1)
    {
        int option_index;
        int c;
        static struct option long_options[] =
            {
                {"keyset", 1, NULL, 'k'},
                {"help", 0, NULL, 'h'},
                {"outdir", 1, NULL, 'o'},
                {"type", 1, NULL, 1},
                {"ncatype", 1, NULL, 2},
                {"titletype", 1, NULL, 3},
                {"tempdir", 1, NULL, 4},
                {"exefsdir", 1, NULL, 5},
                {"romfsdir", 1, NULL, 6},
                {"logodir", 1, NULL, 7},
                {"programnca", 1, NULL, 8},
                {"controlnca", 1, NULL, 9},
                {"legalnca", 1, NULL, 10},
                {"htmldocnca", 1, NULL, 11},
                {"metanca", 1, NULL, 12},
                {"disttype", 1, NULL, 13},
                {"noselfsignncasig2", 0, NULL, 14},
                {"plaintext", 0, NULL, 15},
                {"keygeneration", 1, NULL, 16},
                {"sdkversion", 1, NULL, 17},
                {"keyareakey", 1, NULL, 18},
                {"titleid", 1, NULL, 19},
                {"datanca", 1, NULL, 20},
                {"publicdatanca", 1, NULL, 21},
                {"ncadir", 1, NULL, 22},
                {"digest", 1, NULL, 23},
                {"titleversion", 1, NULL, 24},
                {"cnmt", 1, NULL, 25},
                {"titlekey", 1, NULL, 26},
                {"backupdir", 1, NULL, 27},
                {"ncasig1privatekey", 1, NULL, 28},
                {"acidsigprivatekey", 1, NULL, 29},
                {"ncasig", 1, NULL, 30},
                {"ncasig2privatekey", 1, NULL, 31},
                {"ncasig2modulus", 1, NULL, 32},
                {NULL, 0, NULL, 0},
            };

        c = getopt_long(argc, argv, "k:o:h", long_options, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
        case 'k':
            filepath_set(&keypath, optarg);
            break;
        case 'h':
            usage();
            break;
        case 'o':
            filepath_set(&settings.out_dir, optarg);
            break;
        case 1:
            if (!strcmp(optarg, "nca"))
                settings.file_type = FILE_TYPE_NCA;
            else if (!strcmp(optarg, "nsp"))
                settings.file_type = FILE_TYPE_NSP;
            else
            {
                fprintf(stderr, "Error: invalid type: %s\n", optarg);
                usage();
            }
            break;
        case 2:
            if (!strcmp(optarg, "program"))
                settings.nca_type = NCA_TYPE_PROGRAM;
            else if (!strcmp(optarg, "control"))
                settings.nca_type = NCA_TYPE_CONTROL;
            else if (!strcmp(optarg, "manual"))
                settings.nca_type = NCA_TYPE_MANUAL;
            else if (!strcmp(optarg, "data"))
                settings.nca_type = NCA_TYPE_DATA;
            else if (!strcmp(optarg, "publicdata"))
                settings.nca_type = NCA_TYPE_PUBLICDATA;
            else if (!strcmp(optarg, "meta"))
                settings.nca_type = NCA_TYPE_META;
            else
            {
                fprintf(stderr, "Error: invalid ncatype: %s\n", optarg);
                usage();
            }
            break;
        case 3:
            if (!strcmp(optarg, "application"))
                settings.title_type = TITLE_TYPE_APPLICATION;
            else if (!strcmp(optarg, "addon"))
                settings.title_type = TITLE_TYPE_ADDON;
            else if (!strcmp(optarg, "systemprogram"))
                settings.title_type = TITLE_TYPE_SYSTEMPROGRAM;
            else if (!strcmp(optarg, "systemdata"))
                settings.title_type = TITLE_TYPE_SYSTEMDATA;
            else if (!strcmp(optarg, "patch"))
                settings.title_type = TITLE_TYPE_PATCH;
            else
            {
                fprintf(stderr, "Error: invalid titletype: %s\n", optarg);
                usage();
            }
            break;
        case 4:
            filepath_set(&settings.temp_dir, optarg);
            break;
        case 5:
            filepath_set(&settings.exefs_dir, optarg);
            break;
        case 6:
            filepath_set(&settings.romfs_dir, optarg);
            break;
        case 7:
            filepath_set(&settings.logo_dir, optarg);
            break;
        case 8:
            filepath_set(&settings.programnca, optarg);
            break;
        case 9:
            filepath_set(&settings.controlnca, optarg);
            break;
        case 10:
            filepath_set(&settings.legalnca, optarg);
            break;
        case 11:
            filepath_set(&settings.htmldocnca, optarg);
            break;
        case 12:
            filepath_set(&settings.metanca, optarg);
            break;
        case 13:
            if (!strcmp(optarg, "download"))
                settings.nca_disttype = NCA_DISTRIBUTION_DOWNLOAD;
            else if (!strcmp(optarg, "gamecard"))
                settings.nca_disttype = NCA_DISTRIBUTION_GAMECARD;
            else
            {
                fprintf(stderr, "Error: Invalid disttype: %s\n", optarg);
                usage();
            }
            break;
        case 14:
            settings.noselfsignncasig2 = 1;
            break;
        case 15:
            settings.plaintext = 1;
            break;
        case 16:
            settings.keygeneration = atoi(optarg);
            // Validating Keygeneration
            if (settings.keygeneration < 1 || settings.keygeneration > 32)
            {
                fprintf(stderr, "Invalid keygeneration: %i, keygeneration range: 1-32\n", settings.keygeneration);
                return EXIT_FAILURE;
            }
            break;
        case 17:
            settings.sdk_version = strtoul(optarg, NULL, 16);
            // Validating SDK Version
            if (settings.sdk_version < 0x000B0000)
            {
                fprintf(stderr, "Error: Invalid SDK version: %08" PRIX32 "\n"
                                "SDK version must be equal or greater than: 000B0000\n",
                        settings.sdk_version);
                exit(EXIT_FAILURE);
            }
            break;
        case 18:
            parse_hex_key(settings.keyareakey, optarg, 0x10);
            break;
        case 19:
            settings.title_id = strtoull(optarg, NULL, 16);
            break;
        case 20:
            filepath_set(&settings.datanca, optarg);
            break;
        case 21:
            filepath_set(&settings.publicdatanca, optarg);
            break;
        case 22:
            filepath_set(&settings.ncadir, optarg);
            break;
        case 23:
            parse_hex_key(settings.digest, optarg, 0x20);
            break;
        case 24:
            settings.title_version = strtoul(optarg, NULL, 16);
            break;
        case 25:
            filepath_set(&settings.cnmt, optarg);
            break;
        case 26:
            parse_hex_key(settings.title_key, optarg, 0x10);
            settings.has_title_key = 1;
            break;
        case 27:
            filepath_set(&settings.backup_dir, optarg);
            break;
        case 28:
            filepath_set(&settings.nca_sig1_private_key, optarg);
            break;
        case 29:
            filepath_set(&settings.acid_sig_private_key, optarg);
            break;
        case 30:
            if (!strcmp(optarg, "static"))
                settings.nca_sig = NCA_SIG_TYPE_STATIC;
            else if (!strcmp(optarg, "zero"))
                settings.nca_sig = NCA_SIG_TYPE_ZERO;
            else if (!strcmp(optarg, "random"))
                settings.nca_sig = NCA_SIG_TYPE_RANDOM;
            else
            {
                fprintf(stderr, "Error: Invalid ncasig: %s\n", optarg);
                usage();
            }
            break;
        case 31:
            filepath_set(&settings.nca_sig2_private_key, optarg);
            break;
        case 32:
            filepath_set(&settings.nca_sig2_modulus, optarg);
            break;
        default:
            usage();
        }
    }

    printf("----> Preparing:\n");

    // Try to populate default keyfile.
    FILE *keyfile = NULL;
    if (keypath.valid == VALIDITY_INVALID)
    {
        // Locating default key file
        filepath_set(&keypath, "keys.dat");
        keyfile = os_fopen(keypath.os_path, OS_MODE_READ);
        if (keyfile == NULL)
        {
            filepath_set(&keypath, "keys.txt");
            keyfile = os_fopen(keypath.os_path, OS_MODE_READ);
        }
        if (keyfile == NULL)
        {
            filepath_set(&keypath, "keys.ini");
            keyfile = os_fopen(keypath.os_path, OS_MODE_READ);
        }
        if (keyfile == NULL)
        {
            filepath_set(&keypath, "prod.keys");
            keyfile = os_fopen(keypath.os_path, OS_MODE_READ);
        }
        if (keyfile == NULL)
        {
            /* Use $HOME/.switch/prod.keys if it exists */
            char *home = getenv("HOME");
            if (home == NULL)
                home = getenv("USERPROFILE");
            if (home != NULL)
            {
                filepath_set(&keypath, home);
                filepath_append(&keypath, ".switch");
                filepath_append(&keypath, "prod.keys");
                keyfile = os_fopen(keypath.os_path, OS_MODE_READ);
            }
        }
    }
    else if (keypath.valid == VALIDITY_VALID)
        keyfile = os_fopen(keypath.os_path, OS_MODE_READ);

    // Try to populate keyfile.
    if (keyfile != NULL)
    {
        printf("Loading '%s' keyset file\n", keypath.char_path);
        extkeys_initialize_keyset(&settings.keyset, keyfile);
        pki_derive_keys(&settings.keyset);
        fclose(keyfile);
    }
    else
    {
        printf("\n");
        fprintf(stderr, "Error: Unable to open keyset file\n"
                        "Use -k or --keyset to specify your keyset file path or place your keyset in ." OS_PATH_SEPARATOR "keys.dat\n");
        return EXIT_FAILURE;
    }

    // Make sure that header_key exists
    uint8_t has_header_Key = 0;
    for (unsigned int i = 0; i < 0x10; i++)
    {
        if (settings.keyset.header_key[i] != 0)
        {
            has_header_Key = 1;
            break;
        }
    }
    if (has_header_Key == 0)
    {
        fprintf(stderr, "Error: header_key is not present in keyset file\n");
        return EXIT_FAILURE;
    }

    // Make sure that key_area_key_application_keygen exists
    uint8_t has_kek = 0;
    for (unsigned int kekc = 0; kekc < 0x10; kekc++)
    {
        if (settings.keyset.key_area_keys[settings.keygeneration - 1][0][kekc] != 0)
        {
            has_kek = 1;
            break;
        }
    }
    if (has_kek == 0)
    {
        fprintf(stderr, "Error: key_area_key_application for keygeneration %i is not present in keyset file\n", settings.keygeneration);
        return EXIT_FAILURE;
    }

    // Make sure that titlekek_keygen exists if titlekey is specified
    if (settings.has_title_key == 1)
    {
        uint8_t has_titlekek = 0;
        for (unsigned int tkekc = 0; tkekc < 0x10; tkekc++)
        {
            if (settings.keyset.titlekeks[settings.keygeneration - 1][tkekc] != 0)
            {
                has_titlekek = 1;
                break;
            }
        }
        if (has_titlekek == 0)
        {
            fprintf(stderr, "Error: titlekek for keygeneration %i is not present in keyset file\n", settings.keygeneration);
            return EXIT_FAILURE;
        }
    }

    // Make sure that titleid is within valid range
    if (settings.title_id < 0x0100000000000000)
    {
        fprintf(stderr, "Error: Bad TitleID: %016" PRIx64 "\n"
                        "Valid TitleID range: 0100000000000000 - ffffffffffffffff\n",
                settings.title_id);
        usage();
    }
    if (settings.title_id > 0x01ffffffffffffff)
        printf("Warning: TitleID %" PRIx64 " is greater than 01ffffffffffffff and it's not suggested\n", settings.title_id);

    // Make sure that outout directory is set
    if (settings.out_dir.valid == VALIDITY_INVALID)
    {
        fprintf(stderr, "Error: Output directory is not specified");
        usage();
    }

    if (settings.file_type == FILE_TYPE_NCA)
    {
        // Remove existing temp directory and create a new one
        printf("Removing existing temp directory\n");
        filepath_remove_directory(&settings.temp_dir);
        printf("Creating temp directory\n");
        os_makedir(settings.temp_dir.os_path);

        // Create backup directory
        printf("Creating backup directory\n");
        os_makedir(settings.backup_dir.os_path);
        // Add titleid to backup folder path
        filepath_append(&settings.backup_dir, "%016" PRIx64, settings.title_id);
        os_makedir(settings.backup_dir.os_path);
    }

    // Create output directory
    printf("Creating output directory\n");
    os_makedir(settings.out_dir.os_path);

    printf("\n");

    if (settings.file_type == FILE_TYPE_NCA)
    {
        switch (settings.nca_type)
        {
        case NCA_TYPE_PROGRAM:
            if (settings.exefs_dir.valid == VALIDITY_INVALID)
            {
                fprintf(stderr, "Error: exefs filepath is not set\n");
                usage();
            }
            else if (((settings.nca_sig2_private_key.valid == VALIDITY_VALID) && (settings.nca_sig2_modulus.valid == VALIDITY_INVALID)) || ((settings.nca_sig2_private_key.valid == VALIDITY_INVALID) && (settings.nca_sig2_modulus.valid == VALIDITY_VALID)))
            {
                fprintf(stderr, "Error: Both nca signature 2 private key and public key filepaths must be valid\n");
                usage();
            }
            printf("----> Processing NPDM\n");
            npdm_process(&settings);
            printf("\n");
            nca_create_program(&settings);
            break;
        case NCA_TYPE_CONTROL:
            if (settings.romfs_dir.valid == VALIDITY_INVALID)
                usage();
            else if (settings.has_title_key)
            {
                fprintf(stderr, "Error: Titlekey is not supported for control nca\n");
                usage();
            }
            printf("----> Processing NACP\n");
            nacp_process(&settings);
            printf("\n");
            nca_create_romfs_type(&settings, nca_romfs_get_type(settings.nca_type));
            break;
        case NCA_TYPE_DATA:
            if (settings.romfs_dir.valid == VALIDITY_INVALID)
                usage();
            else if (settings.has_title_key)
            {
                fprintf(stderr, "Error: Titlekey is not supported for data nca\n");
                usage();
            }
            nca_create_romfs_type(&settings, nca_romfs_get_type(settings.nca_type));
            break;
        case NCA_TYPE_MANUAL:
            if (settings.romfs_dir.valid == VALIDITY_INVALID)
                usage();
            nca_create_romfs_type(&settings, nca_romfs_get_type(settings.nca_type));
            break;
        case NCA_TYPE_PUBLICDATA:
            if (settings.romfs_dir.valid == VALIDITY_INVALID)
                usage();
            nca_create_romfs_type(&settings, nca_romfs_get_type(settings.nca_type));
            break;
        case NCA_TYPE_META:
            if (settings.cnmt.valid == VALIDITY_VALID)
                nca_create_meta(&settings);
            else if (settings.title_type == 0)
            {
                fprintf(stderr, "Error: invalid titletype\n");
                usage();
            }
            else if (settings.has_title_key)
            {
                fprintf(stderr, "Error: Titlekey is not supported for metadata nca\n");
                usage();
            }
            else if ((settings.programnca.valid == VALIDITY_INVALID || settings.controlnca.valid == VALIDITY_INVALID) && settings.title_type == TITLE_TYPE_APPLICATION)
            {
                fprintf(stderr, "Error: --programnca and/or --controlnca is not set\n");
                usage();
            }
            else if (settings.title_type == TITLE_TYPE_ADDON && settings.publicdatanca.valid == VALIDITY_INVALID)
            {
                fprintf(stderr, "Error: --publicdatanca is not set\n");
                usage();
            }
            else if (settings.title_type == TITLE_TYPE_SYSTEMPROGRAM && settings.programnca.valid == VALIDITY_INVALID)
            {
                fprintf(stderr, "Error: --programnca is not set\n");
                usage();
            }
            else if (settings.title_type == TITLE_TYPE_SYSTEMDATA && settings.datanca.valid == VALIDITY_INVALID)
            {
                fprintf(stderr, "Error: --datanca is not set\n");
                usage();
            }
            else
                nca_create_meta(&settings);
            break;
        default:
            usage();
        }
    }
    else if (settings.file_type == FILE_TYPE_NSP)
    {
        if (settings.ncadir.valid != VALIDITY_INVALID)
        {
            // Create NSP
            printf("----> Creating NSP:\n");
            filepath_t nsp_file_path;
            filepath_init(&nsp_file_path);
            filepath_copy(&nsp_file_path, &settings.out_dir);
            filepath_append(&nsp_file_path, "%016" PRIx64 ".nsp", settings.title_id);
            uint64_t pfs0_size;
            pfs0_build(&settings.ncadir, &nsp_file_path, &pfs0_size);
            printf("\n----> Created NSP: %s\n", nsp_file_path.char_path);
        }
        else
        {
            fprintf(stderr, "Error: --ncadir is not set\n");
            usage();
        }
    }
    else
    {
        fprintf(stderr, "Error: --type is not set\n");
        usage();
    }

    // Remove temp directory
    if (settings.file_type == FILE_TYPE_NCA)
    {
        printf("\n");
        printf("Removing created temp directory\n");
        filepath_remove_directory(&settings.temp_dir);
    }

    printf("\nDone.\n");

    free(settings.keyareakey);
    return EXIT_SUCCESS;
}
