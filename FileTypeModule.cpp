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
#include <windows.h>
#include <sstream>
#include <stdlib.h>

// Framework includes
#include "TskModuleDev.h"

// Poco includes
#include "Poco/UnicodeConverter.h"

// Magic includes
#include "magic.h"

static const uint32_t FILE_BUFFER_SIZE = 1024;

static magic_t magicHandle = NULL;

extern "C" 
{
    /**
     * Module identification function. 
     *
     * @return The name of the module.
     */
    TSK_MODULE_EXPORT const char *name()
    {
        return "FileTypeSigModule";
    }

    /**
     * Module identification function. 
     *
     * @return A description of the module.
     */
    TSK_MODULE_EXPORT const char *description()
    {
        return "Determines file type based on signature using libmagic";
    }

    /**
     * Module identification function. 
     *
     * @return The version of the module.
     */
    TSK_MODULE_EXPORT const char *version()
    {
        return "0.0.0";
    }

    /**
     * Module initialization function. Takes a string as input that allows
     * arguments to be passed into the module.
     * @param arguments Tells the module which
     */
    TskModule::Status TSK_MODULE_EXPORT initialize(const char* arguments)
    {
        magicHandle = magic_open(MAGIC_NONE);
        
        std::string path = GetSystemProperty(TskSystemProperties::MODULE_DIR) + "/" + name() + "/magic.mgc";

        if (magic_load(magicHandle, path.c_str())) {
            std::wstringstream msg;
            msg << L"Error initializing file type module: " << magic_error(magicHandle) << GetSystemPropertyW(TskSystemProperties::MODULE_DIR);
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
            LOGERROR(L"File type module passed NULL file pointer.");
            return TskModule::FAIL;
        }

        if (pFile->getSize() == 0)
            return TskModule::OK;

        try
        {
            char buffer[FILE_BUFFER_SIZE];
            char *type;

            //Do that magic magic
            ssize_t readLen = pFile->read(buffer, FILE_BUFFER_SIZE);
            // we shouldn't get zero as a return value since we know the file is not 0 sized at this point
            if (readLen == 0) {
                std::wstringstream msg;
                msg << L"Error reading file contents";
                LOGERROR(msg.str());
                return TskModule::FAIL;
            }

            if (!(type = const_cast<char *>(magic_buffer(magicHandle, buffer, readLen))) && !magic_error(magicHandle)) {
                std::wstringstream msg;
                msg << L"Error initializing file type module: " << magic_error(magicHandle);
                LOGERROR(msg.str());
                return TskModule::FAIL;
            }

            // Add to blackboard
            TskBlackboardAttribute attr(TSK_FILE_TYPE_SIG, name(), "", type);
            pFile->addGenInfoAttribute(attr);
        }
        catch (TskException& tskEx)
        {
            std::wstringstream msg;
            msg << L"FileTypeModule - Caught framework exception: " << tskEx.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        catch (std::exception& ex)
        {
            std::wstringstream msg;
            msg << L"FileTypeModule - Caught exception: " << ex.what();
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
