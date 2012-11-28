/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file FileTypeSigModule.cpp
 * Contains the module that uses libmagic to determine the
 * file type based on signatures.
 */

// System includes
#include <string>
#ifdef TSK_WIN32
#include <windows.h>
#endif
#include <sstream>
#include <stdlib.h>
#include <string.h>

// Framework includes
#include "TskModuleDev.h"

// Poco includes
#include "Poco/UnicodeConverter.h"
#include "Poco/File.h"
#include "Poco/Path.h"

// Magic includes
#include "magic.h"

namespace 
{
    const char *MODULE_NAME = "FileTypeSigModule";
    const char *MODULE_DESCRIPTION = "Determines file type based on signature using libmagic";
    const char *MODULE_VERSION = "1.0.0";

  static const uint32_t FILE_BUFFER_SIZE = 1024;

  static magic_t magicHandle = NULL;
}

extern "C" 
{
    /**
     * Module identification function. 
     *
     * @return The name of the module.
     */
    TSK_MODULE_EXPORT const char *name() 
    {
        return MODULE_NAME;
    }

    /**
     * Module identification function. 
     *
     * @return A description of the module.
     */
    TSK_MODULE_EXPORT const char *description()
    {
        return MODULE_DESCRIPTION;
    }

    /**
     * Module identification function. 
     *
     * @return The version of the module.
     */
    TSK_MODULE_EXPORT const char *version()
    {
        return MODULE_VERSION;
    }

    /**
     * Module initialization function. Takes a string as input that allows
     * arguments to be passed into the module.
     * @param arguments Tells the module which
     */
    TskModule::Status TSK_MODULE_EXPORT initialize(const char* arguments)
    {
        magicHandle = magic_open(MAGIC_NONE);
        
        std::string path = GetSystemProperty(TskSystemProperties::MODULE_DIR) + Poco::Path::separator() + MODULE_NAME + Poco::Path::separator() + "magic.mgc";

        Poco::File magicFile = Poco::File(path);
        if (magicFile.exists() == false) {
            std::stringstream msg;
            msg << "FileTypeSigModule: Magic file not found: " << path;
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }

        if (magic_load(magicHandle, path.c_str())) {
            std::stringstream msg;
            msg << "FileTypeSigModule: Error loading magic file: " << magic_error(magicHandle) << GetSystemProperty(TskSystemProperties::MODULE_DIR);
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }

        return TskModule::OK;
    }

    /**
     * The run() method is where the module's work is performed.
     * The module will be passed a pointer to a file from which both
     * content and metadata can be retrieved.
     * @param pFile A pointer to a file to be processed.
     * @returns TskModule::OK on success and TskModule::FAIL on error.
     */
    TskModule::Status TSK_MODULE_EXPORT run(TskFile * pFile)
    {
        if (pFile == NULL)
        {
            LOGERROR("FileTypeSigModule: Passed NULL file pointer.");
            return TskModule::FAIL;
        }

        if (pFile->getSize() == 0)
            return TskModule::OK;

        try
        {
            char buffer[FILE_BUFFER_SIZE];

            //Do that magic magic
            ssize_t readLen = pFile->read(buffer, FILE_BUFFER_SIZE);
            // we shouldn't get zero as a return value since we know the file is not 0 sized at this point
            if (readLen <= 0) {
                std::stringstream msg;
                msg << "FileTypeSigModule: Error reading file contents";
                LOGERROR(msg.str());
                return TskModule::FAIL;
            }

            const char *type = magic_buffer(magicHandle, buffer, readLen);
            if (type == NULL) {
                std::stringstream msg;
                msg << "FileTypeSigModule: Error getting file type: " << magic_error(magicHandle);
                LOGERROR(msg.str());
                return TskModule::FAIL;
            }

            // clean up type -- we've seen invalid UTF-8 data being returned
            char cleanType[1024];
            cleanType[1023] = '\0';
            strncpy(cleanType, type, 1023);
            TskUtilities::cleanUTF8(cleanType);

            // Add to blackboard
            TskBlackboardAttribute attr(TSK_FILE_TYPE_SIG, MODULE_NAME, "", cleanType);
            pFile->addGenInfoAttribute(attr);
        }
        catch (TskException& tskEx)
        {
            std::stringstream msg;
            msg << "FileTypeModule: Caught framework exception: " << tskEx.message();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        catch (std::exception& ex)
        {
            std::stringstream msg;
            msg << "FileTypeModule: Caught exception: " << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }

        return TskModule::OK;
    }

    TskModule::Status TSK_MODULE_EXPORT finalize()
    {
        return TskModule::OK;
    }
}
