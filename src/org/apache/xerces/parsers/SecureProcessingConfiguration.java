/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.xerces.parsers;

import java.io.File;
import java.io.FileInputStream;
import java.io.FilterInputStream;
import java.io.FilterReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.net.URL;
import java.util.Properties;

import org.apache.xerces.impl.Constants;
import org.apache.xerces.impl.XMLEntityDescription;
import org.apache.xerces.impl.XMLErrorReporter;
import org.apache.xerces.impl.msg.XMLMessageFormatter;
import org.apache.xerces.util.SecurityManager;
import org.apache.xerces.util.SymbolTable;
import org.apache.xerces.xni.Augmentations;
import org.apache.xerces.xni.XMLDTDHandler;
import org.apache.xerces.xni.XMLLocator;
import org.apache.xerces.xni.XMLResourceIdentifier;
import org.apache.xerces.xni.XMLString;
import org.apache.xerces.xni.XNIException;
import org.apache.xerces.xni.grammars.XMLGrammarPool;
import org.apache.xerces.xni.parser.XMLComponentManager;
import org.apache.xerces.xni.parser.XMLConfigurationException;
import org.apache.xerces.xni.parser.XMLDTDFilter;
import org.apache.xerces.xni.parser.XMLDTDSource;
import org.apache.xerces.xni.parser.XMLEntityResolver;
import org.apache.xerces.xni.parser.XMLInputSource;

/**
 * This configuration enhances Xerces support for the JAXP secure processing feature.
 * 
 * @author Michael Glavassevich, IBM
 * 
 * @version $Id$
 */
public final class SecureProcessingConfiguration extends
        XIncludeAwareParserConfiguration {
    
    //
    // Constants
    //
    
    /** Property identifier: security manager. */
    private static final String SECURITY_MANAGER_PROPERTY =
            Constants.XERCES_PROPERTY_PREFIX + Constants.SECURITY_MANAGER_PROPERTY;
    
    /** Property identifier: entity resolver. */
    private static final String ENTITY_RESOLVER_PROPERTY = 
        Constants.XERCES_PROPERTY_PREFIX + Constants.ENTITY_RESOLVER_PROPERTY;
    
    /** Property identifier: access external DTD */
    private static final String ACCESS_EXTERNAL_DTD_PROPERTY =
        Constants.JAXP_JAVAX_PROPERTY_PREFIX + Constants.ACCESS_EXTERNAL_DTD;
    
    /** Property identifier: access external schema */
    private static final String ACCESS_EXTERNAL_SCHEMA_PROPERTY =
        Constants.JAXP_JAVAX_PROPERTY_PREFIX + Constants.ACCESS_EXTERNAL_SCHEMA;
    
    /** Property identifier: element attribute limit */
    private static final String ELEMENT_ATTRIBUTE_LIMIT_PROPERTY =
        Constants.XERCES_PROPERTY_PREFIX + Constants.ELEMENT_ATTRIBUTE_LIMIT_PROPERTY;

    /** Property identifier: alternate element attribute limit */
    private static final String ELEMENT_ATTRIBUTE_LIMIT_PROPERTY2 =
            Constants.JAXP_ORACLE_PROPERTY_PREFIX + Constants.ELEMENT_ATTRIBUTE_LIMIT_PROPERTY;
    
    /** Property identifier: entity expansion limit */
    private static final String ENTITY_EXPANSION_LIMIT_PROPERTY = 
        Constants.XERCES_PROPERTY_PREFIX + Constants.ENTITY_EXPANSION_LIMIT_PROPERTY;

    /** Property identifier: entity expansion limit */
    private static final String ENTITY_EXPANSION_LIMIT_PROPERTY2 = 
            Constants.JAXP_ORACLE_PROPERTY_PREFIX + Constants.ENTITY_EXPANSION_LIMIT_PROPERTY2;
    
    /** Feature identifier: disallow DTDs. */
    protected static final String DISALLOW_DOCTYPE_DECL_FEATURE_FEATURE =
        Constants.XERCES_FEATURE_PREFIX + Constants.DISALLOW_DOCTYPE_DECL_FEATURE;
    
    /** Feature identifier: external general entities. */
    private static final String EXTERNAL_GENERAL_ENTITIES_FEATURE =
        Constants.SAX_FEATURE_PREFIX + Constants.EXTERNAL_GENERAL_ENTITIES_FEATURE;

    /** Feature identifier: external parameter entities. */
    private static final String EXTERNAL_PARAMETER_ENTITIES_FEATURE =
        Constants.SAX_FEATURE_PREFIX + Constants.EXTERNAL_PARAMETER_ENTITIES_FEATURE;
    
    /** Feature identifier: load external DTD. */
    private static final String LOAD_EXTERNAL_DTD_FEATURE =
        Constants.XERCES_FEATURE_PREFIX + Constants.LOAD_EXTERNAL_DTD_FEATURE;
    
    private static final String ACCESS_NO_PROTOCOLS = "";
    private static final String ACCESS_ALL_PROTOCOLS = "all";
    
    /** Set to true for debugging */
    private static final boolean DEBUG = isDebugEnabled();
    
    /** Cache the contents of the jaxp.properties file, if used. */
    private static Properties jaxpProperties = null;

    /** Cache the timestamp of the jaxp.properties file, if used. */
    private static long lastModified = -1;
    
    /** System properties */
    private static final String ACCESS_EXTERNAL_DTD_PROPERTY_NAME = "javax.xml.accessExternalDTD";
    private static final String ACCESS_EXTERNAL_SCHEMA_PROPERTY_NAME = "javax.xml.accessExternalSchema";
    private static final String ELEMENT_ATTRIBUTE_LIMIT_PROPERTY_NAME = "jdk.xml.elementAttributeLimit";
    private static final String ENTITY_EXPANSION_LIMIT_PROPERTY_NAME = "jdk.xml.entityExpansionLimit";
    private static final String MAX_ELEMENT_DEPTH_PROPERTY_NAME = "jdk.xml.maxElementDepth";
    private static final String MAX_OCCUR_LIMIT_PROPERTY_NAME = "jdk.xml.maxOccur";
    private static final String MAX_GENERAL_ENTITY_SIZE_LIMIT_PROPERTY_NAME = "jdk.xml.maxGeneralEntitySizeLimit";
    private static final String MAX_PARAMETER_ENTITY_SIZE_LIMIT_PROPERTY_NAME = "jdk.xml.maxParameterEntitySizeLimit";
    private static final String MAX_TOTAL_ENTITY_SIZE_LIMIT_PROPERTY_NAME = "jdk.xml.totalEntitySizeLimit";
    private static final String RESOLVE_EXTERNAL_ENTITIES_PROPERTY_NAME = "jdk.xml.resolveExternalEntities";

    /** Default values */
    private static final String ACCESS_EXTERNAL_DTD_DEFAULT_VALUE = "all";
    private static final String ACCESS_EXTERNAL_SCHEMA_DEFAULT_VAULE = "all";
    private static final int ELEMENT_ATTRIBUTE_LIMIT_DEFAULT_VALUE = 10000;
    private static final int ENTITY_EXPANSION_LIMIT_DEFAULT_VALUE = 64000;
    private static final int MAX_ELEMENT_DEPTH_DEFAULT_VALUE = Integer.MAX_VALUE;
    private static final int MAX_OCCUR_LIMIT_DEFAULT_VALUE = 5000;
    private static final int MAX_GENERAL_ENTITY_SIZE_LIMIT_DEFAULT_VALUE = Integer.MAX_VALUE;
    private static final int MAX_PARAMETER_ENTITY_SIZE_LIMIT_DEFAULT_VALUE = 1000000;
    private static final int MAX_TOTAL_ENTITY_SIZE_LIMIT_DEFAULT_VALUE = 50000000;
    private static final boolean RESOLVE_EXTERNAL_ENTITIES_DEFAULT_VALUE = false;   
    
    /** Xerces SecurityManager default value for entity expansion limit. **/
    private static final int SECURITY_MANAGER_DEFAULT_ENTITY_EXPANSION_LIMIT = 100000;
    
    /** Xerces SecurityManager default value of number of nodes created. **/
    private static final int SECURITY_MANAGER_DEFAULT_MAX_OCCUR_NODE_LIMIT = 3000;
    
    
    protected final String ACCESS_EXTERNAL_DTD_SYSTEM_VALUE;
    protected final String ACCESS_EXTERNAL_SCHEMA_SYSTEM_VALUE;
    protected final int ELEMENT_ATTRIBUTE_LIMIT_SYSTEM_VALUE;
    protected final int ENTITY_EXPANSION_LIMIT_SYSTEM_VALUE;
    protected final int MAX_ELEMENT_DEPTH_SYSTEM_VALUE;
    protected final int MAX_OCCUR_LIMIT_SYSTEM_VALUE;
    protected final int MAX_GENERAL_ENTITY_SIZE_LIMIT_SYSTEM_VALUE;
    protected final int MAX_PARAMETER_ENTITY_SIZE_LIMIT_SYSTEM_VALUE;
    protected final int MAX_TOTAL_ENTITY_SIZE_LIMIT_SYSTEM_VALUE;
    protected final boolean RESOLVE_EXTERNAL_ENTITIES_SYSTEM_VALUE;

    //
    // Fields
    //
    
    private final boolean fJavaSecurityManagerEnabled;
    private boolean fLimitSpecified;
    private SecurityManager fSecurityManager;
    private InternalEntityMonitor fInternalEntityMonitor;
    private final ExternalEntityMonitor fExternalEntityMonitor;
    private int fTotalEntitySize = 0;
    
    /** Default constructor. */
    public SecureProcessingConfiguration() {
        this(null, null, null);
    } // <init>()
    
    /** 
     * Constructs a parser configuration using the specified symbol table. 
     *
     * @param symbolTable The symbol table to use.
     */
    public SecureProcessingConfiguration(SymbolTable symbolTable) {
        this(symbolTable, null, null);
    } // <init>(SymbolTable)
    
    /**
     * Constructs a parser configuration using the specified symbol table and
     * grammar pool.
     * <p>
     *
     * @param symbolTable The symbol table to use.
     * @param grammarPool The grammar pool to use.
     */
    public SecureProcessingConfiguration(
            SymbolTable symbolTable,
            XMLGrammarPool grammarPool) {
        this(symbolTable, grammarPool, null); 
    } // <init>(SymbolTable,XMLGrammarPool)
    
    /**
     * Constructs a parser configuration using the specified symbol table,
     * grammar pool, and parent settings.
     * <p>
     *
     * @param symbolTable    The symbol table to use.
     * @param grammarPool    The grammar pool to use.
     * @param parentSettings The parent settings.
     */
    public SecureProcessingConfiguration(
            SymbolTable symbolTable,
            XMLGrammarPool grammarPool,
            XMLComponentManager parentSettings) {
        
        super(symbolTable, grammarPool, parentSettings);
        fJavaSecurityManagerEnabled = (System.getSecurityManager() != null);
        fSecurityManager = new org.apache.xerces.util.SecurityManager();
        super.setProperty(SECURITY_MANAGER_PROPERTY, fSecurityManager);
        
        ELEMENT_ATTRIBUTE_LIMIT_SYSTEM_VALUE = getPropertyValue(ELEMENT_ATTRIBUTE_LIMIT_PROPERTY_NAME, ELEMENT_ATTRIBUTE_LIMIT_DEFAULT_VALUE);
        ENTITY_EXPANSION_LIMIT_SYSTEM_VALUE = getPropertyValue(ENTITY_EXPANSION_LIMIT_PROPERTY_NAME, ENTITY_EXPANSION_LIMIT_DEFAULT_VALUE);
        MAX_ELEMENT_DEPTH_SYSTEM_VALUE = getPropertyValue(MAX_ELEMENT_DEPTH_PROPERTY_NAME, MAX_ELEMENT_DEPTH_DEFAULT_VALUE);
        MAX_OCCUR_LIMIT_SYSTEM_VALUE = getPropertyValue(MAX_OCCUR_LIMIT_PROPERTY_NAME, MAX_OCCUR_LIMIT_DEFAULT_VALUE);
        MAX_GENERAL_ENTITY_SIZE_LIMIT_SYSTEM_VALUE = getPropertyValue(MAX_GENERAL_ENTITY_SIZE_LIMIT_PROPERTY_NAME, MAX_GENERAL_ENTITY_SIZE_LIMIT_DEFAULT_VALUE);
        MAX_PARAMETER_ENTITY_SIZE_LIMIT_SYSTEM_VALUE = getPropertyValue(MAX_PARAMETER_ENTITY_SIZE_LIMIT_PROPERTY_NAME, MAX_PARAMETER_ENTITY_SIZE_LIMIT_DEFAULT_VALUE);
        MAX_TOTAL_ENTITY_SIZE_LIMIT_SYSTEM_VALUE = getPropertyValue(MAX_TOTAL_ENTITY_SIZE_LIMIT_PROPERTY_NAME, MAX_TOTAL_ENTITY_SIZE_LIMIT_DEFAULT_VALUE);
        fSecurityManager.setEntityExpansionLimit(ENTITY_EXPANSION_LIMIT_SYSTEM_VALUE);
        fSecurityManager.setElementAttributeLimit(ELEMENT_ATTRIBUTE_LIMIT_SYSTEM_VALUE);
        fSecurityManager.setMaxOccurNodeLimit(MAX_OCCUR_LIMIT_SYSTEM_VALUE);
        fSecurityManager.setGeneralEntitySizeLimit(MAX_GENERAL_ENTITY_SIZE_LIMIT_SYSTEM_VALUE);
        fSecurityManager.setParameterEntitySizeLimit(MAX_PARAMETER_ENTITY_SIZE_LIMIT_SYSTEM_VALUE);
        fSecurityManager.setTotalEntitySizeLimit(MAX_TOTAL_ENTITY_SIZE_LIMIT_SYSTEM_VALUE);
        fSecurityManager.setMaxElementDepth(MAX_ELEMENT_DEPTH_SYSTEM_VALUE);
        
        RESOLVE_EXTERNAL_ENTITIES_SYSTEM_VALUE = getPropertyValue(RESOLVE_EXTERNAL_ENTITIES_PROPERTY_NAME, RESOLVE_EXTERNAL_ENTITIES_DEFAULT_VALUE);
        if (!RESOLVE_EXTERNAL_ENTITIES_SYSTEM_VALUE) {
            super.setFeature(EXTERNAL_GENERAL_ENTITIES_FEATURE, false);
            super.setFeature(EXTERNAL_PARAMETER_ENTITIES_FEATURE, false);
            super.setFeature(LOAD_EXTERNAL_DTD_FEATURE, false);
            super.setProperty(ACCESS_EXTERNAL_DTD_PROPERTY, ACCESS_NO_PROTOCOLS);
            super.setProperty(ACCESS_EXTERNAL_SCHEMA_PROPERTY, ACCESS_NO_PROTOCOLS);
            fSecurityManager.setAccessExternalDTD(ACCESS_NO_PROTOCOLS);
            fSecurityManager.setAccessExternalSchema(ACCESS_NO_PROTOCOLS);
        }
        else
        {
            super.setFeature(EXTERNAL_GENERAL_ENTITIES_FEATURE, true);
            super.setFeature(EXTERNAL_PARAMETER_ENTITIES_FEATURE, true);
            super.setFeature(LOAD_EXTERNAL_DTD_FEATURE, true);
            super.setProperty(ACCESS_EXTERNAL_DTD_PROPERTY, ACCESS_ALL_PROTOCOLS);
            super.setProperty(ACCESS_EXTERNAL_SCHEMA_PROPERTY, ACCESS_ALL_PROTOCOLS);
            fSecurityManager.setAccessExternalDTD(ACCESS_ALL_PROTOCOLS);
            fSecurityManager.setAccessExternalSchema(ACCESS_ALL_PROTOCOLS);
        }
        
        ACCESS_EXTERNAL_DTD_SYSTEM_VALUE = getPropertyValue(ACCESS_EXTERNAL_DTD_PROPERTY_NAME, ACCESS_EXTERNAL_DTD_DEFAULT_VALUE);
        if (fLimitSpecified) {
            super.setProperty(ACCESS_EXTERNAL_DTD_PROPERTY, ACCESS_EXTERNAL_DTD_SYSTEM_VALUE);
            fSecurityManager.setAccessExternalDTD(ACCESS_EXTERNAL_DTD_SYSTEM_VALUE);
        }
        ACCESS_EXTERNAL_SCHEMA_SYSTEM_VALUE = getPropertyValue(ACCESS_EXTERNAL_SCHEMA_PROPERTY_NAME, ACCESS_EXTERNAL_SCHEMA_DEFAULT_VAULE);
        if (fLimitSpecified) {
            super.setProperty(ACCESS_EXTERNAL_SCHEMA_PROPERTY, ACCESS_EXTERNAL_SCHEMA_SYSTEM_VALUE);
            fSecurityManager.setAccessExternalSchema(ACCESS_EXTERNAL_SCHEMA_SYSTEM_VALUE);
        }

        super.setFeature(DISALLOW_DOCTYPE_DECL_FEATURE_FEATURE, true);
        fExternalEntityMonitor = new ExternalEntityMonitor();
        super.setProperty(ENTITY_RESOLVER_PROPERTY, fExternalEntityMonitor);
        
        // add default recognized properties
        final String[] recognizedProperties =
        {                    
            ELEMENT_ATTRIBUTE_LIMIT_PROPERTY,
            ELEMENT_ATTRIBUTE_LIMIT_PROPERTY2
        };
        addRecognizedProperties(recognizedProperties);
    }
    
    protected void checkEntitySizeLimits(int sizeOfEntity, int delta, boolean isPE) {
        fTotalEntitySize += delta;
        if (fTotalEntitySize > fSecurityManager.getTotalEntitySizeLimit()) {
            fErrorReporter.reportError(XMLMessageFormatter.XML_DOMAIN,
                    "TotalEntitySizeLimitExceeded",
                    new Object[] {new Integer(fSecurityManager.getTotalEntitySizeLimit())},
                    XMLErrorReporter.SEVERITY_FATAL_ERROR);
        }
        if (isPE) {
            if (sizeOfEntity > fSecurityManager.getParameterEntitySizeLimit()) {
                fErrorReporter.reportError(XMLMessageFormatter.XML_DOMAIN,
                        "MaxParameterEntitySizeLimitExceeded",
                        new Object[] {new Integer(fSecurityManager.getParameterEntitySizeLimit())},
                        XMLErrorReporter.SEVERITY_FATAL_ERROR);
            }
        }
        else if (sizeOfEntity > fSecurityManager.getGeneralEntitySizeLimit()) {
            fErrorReporter.reportError(XMLMessageFormatter.XML_DOMAIN,
                    "MaxGeneralEntitySizeLimitExceeded",
                    new Object[] {new Integer(fSecurityManager.getGeneralEntitySizeLimit())},
                    XMLErrorReporter.SEVERITY_FATAL_ERROR);
        }
    }
    
    /**
     * Returns the value of a property.
     * 
     * @param propertyId The property identifier.
     * @return the value of the property
     * 
     * @throws XMLConfigurationException Thrown for configuration error.
     *                                   In general, components should
     *                                   only throw this exception if
     *                                   it is <strong>really</strong>
     *                                   a critical error.
     */
    public Object getProperty(String propertyId)
        throws XMLConfigurationException {
        if (SECURITY_MANAGER_PROPERTY.equals(propertyId)) {
            return fSecurityManager;
        }
        else if (ENTITY_RESOLVER_PROPERTY.equals(propertyId)) {
            return fExternalEntityMonitor;
        }
        Object o = fSecurityManager.getIfManagedBySecurityManager(propertyId);
        if (o != null)
        {
            return o;
        }
        return super.getProperty(propertyId);
    }
    
    /**
     * setProperty
     * 
     * @param propertyId 
     * @param value 
     */
    public void setProperty(String propertyId, Object value)
        throws XMLConfigurationException {
        if (SECURITY_MANAGER_PROPERTY.equals(propertyId)) {
            // Do not allow the Xerces SecurityManager to be 
            // removed if the Java SecurityManager has been installed.
            if (value == null && fJavaSecurityManagerEnabled) {
                return;
            }
            fSecurityManager = (SecurityManager) value;
            if (fSecurityManager != null) {
                // Override SecurityManager default values with the system property / jaxp.properties / config default determined values.
                if (fSecurityManager.getEntityExpansionLimit() == SECURITY_MANAGER_DEFAULT_ENTITY_EXPANSION_LIMIT) {
                    fSecurityManager.setEntityExpansionLimit(ENTITY_EXPANSION_LIMIT_SYSTEM_VALUE);
                }
                if (fSecurityManager.getMaxOccurNodeLimit() == SECURITY_MANAGER_DEFAULT_MAX_OCCUR_NODE_LIMIT) {
                    fSecurityManager.setMaxOccurNodeLimit(MAX_OCCUR_LIMIT_SYSTEM_VALUE);
                }
                fSecurityManager.setMaxElementDepth(MAX_ELEMENT_DEPTH_SYSTEM_VALUE);
            }  
        }
        else if (ENTITY_RESOLVER_PROPERTY.equals(propertyId)) {
            fExternalEntityMonitor.setEntityResolver((XMLEntityResolver) value);
        }
        if (ENTITY_EXPANSION_LIMIT_PROPERTY.equals(propertyId) || ENTITY_EXPANSION_LIMIT_PROPERTY2.equals(propertyId))
        {
            if (value instanceof Integer)
            {
                fSecurityManager.setEntityExpansionLimit(Integer.class.cast(value).intValue());
            }
            else
            {
                fSecurityManager.setEntityExpansionLimit(Integer.parseInt(String.class.cast(value)));
            }
        }
        if (ELEMENT_ATTRIBUTE_LIMIT_PROPERTY.equals(propertyId) || ELEMENT_ATTRIBUTE_LIMIT_PROPERTY2.equals(propertyId))
        {
            if (value instanceof Integer)
            {
                fSecurityManager.setElementAttributeLimit(Integer.class.cast(value).intValue());
            }
            else
            {
                fSecurityManager.setElementAttributeLimit(Integer.parseInt(String.class.cast(value)));
            }
        }
        super.setProperty(propertyId, value);
    }
    
    /** Configures the XML 1.0 pipeline. */
    protected void configurePipeline() {
        super.configurePipeline();
        configurePipelineCommon();
    }
    
    /** Configures the XML 1.1 pipeline. */
    protected void configureXML11Pipeline() {
        super.configureXML11Pipeline();
        configurePipelineCommon();
        if (fXML11DTDScanner != null && fInternalEntityMonitor != null) {
            fXML11DTDScanner.setDTDHandler(fInternalEntityMonitor);
            fInternalEntityMonitor.setDTDSource(fXML11DTDScanner);
            fInternalEntityMonitor.setDTDHandler(fXML11DTDProcessor);
            fXML11DTDProcessor.setDTDSource(fInternalEntityMonitor);
        }
    }
    
    private void configurePipelineCommon() {
        if (fSecurityManager != null) {
            fTotalEntitySize = 0;
            if (fInternalEntityMonitor == null) {
                fInternalEntityMonitor = new InternalEntityMonitor();
            }
            // Reconfigure DTD pipeline. Insert internal entity decl monitor.
            fDTDScanner.setDTDHandler(fInternalEntityMonitor);
            fInternalEntityMonitor.setDTDSource(fDTDScanner);
            fInternalEntityMonitor.setDTDHandler(fDTDProcessor);
            fDTDProcessor.setDTDSource(fInternalEntityMonitor);
        }
    }
    
    private int getPropertyValue(String propertyName, int defaultValue) {
        
        fLimitSpecified = false;
        
        // Step #1: Use the system property first
        try {
            String propertyValue = SecuritySupport.getSystemProperty(propertyName);
            if (propertyValue != null && propertyValue.length() >= 0) {
                if (DEBUG) {
                    debugPrintln("found system property \"" + propertyName + "\", value=" + propertyValue);
                }
                final int intValue = Integer.parseInt(propertyValue);
                fLimitSpecified = true;
                if (intValue > 0) {
                    return intValue;
                }
                // Treat 0 and negative numbers as no limit (i.e. max integer).
                return Integer.MAX_VALUE;
            }
        }
        // The VM ran out of memory or there was some other serious problem. Re-throw.
        catch (VirtualMachineError vme) {
            throw vme;
        }
        // ThreadDeath should always be re-thrown
        catch (ThreadDeath td) {
            throw td;
        }
        catch (Throwable e) {
            // Ignore all other exceptions/errors and continue w/ next location
            if (DEBUG) {
                debugPrintln(e.getClass().getName() + ": " + e.getMessage());
                e.printStackTrace();
            }
        }
        
        // Step #2: Use $java.home/lib/jaxp.properties
        try {
            boolean fExists = false;
            File f = null;
            try {               
                String javah = SecuritySupport.getSystemProperty("java.home");
                String configFile = javah + File.separator +
                        "lib" + File.separator + "jaxp.properties";

                f = new File(configFile);
                fExists = SecuritySupport.getFileExists(f);

            }
            catch (SecurityException se) {
                // If there is a security exception, move on to next location.
                lastModified = -1;
                jaxpProperties = null;            
            }

            synchronized (SecureProcessingConfiguration.class) {    

                boolean runBlock = false;
                FileInputStream fis = null;

                try {
                    if (lastModified >= 0) {
                        // File has been modified, or didn't previously exist. 
                        // Need to reload properties    
                        if ((fExists) &&
                            (lastModified < (lastModified = SecuritySupport.getLastModified(f)))) {  
                            runBlock = true;
                        } 
                        else {
                            if (!fExists) {
                                // file existed, but it's been deleted.
                                lastModified = -1;
                                jaxpProperties = null;
                            }
                        }        
                    } 
                    else {
                        if (fExists) { 
                            // File didn't exist, but it does now.
                            runBlock = true;
                            lastModified = SecuritySupport.getLastModified(f);
                        }    
                    }

                    if (runBlock == true) {
                        // Try to read from $java.home/lib/jaxp.properties
                        jaxpProperties = new Properties();

                        fis = SecuritySupport.getFileInputStream(f);
                        jaxpProperties.load(fis);
                    }       

                }
                catch (Exception x) {
                    lastModified = -1;
                    jaxpProperties = null;
                    // assert(x instanceof FileNotFoundException
                    //        || x instanceof SecurityException)
                    // In both cases, ignore and return the default value
                }
                finally {
                    // try to close the input stream if one was opened.
                    if (fis != null) {
                        try {
                            fis.close();
                        }
                        // Ignore the exception.
                        catch (IOException exc) {}
                    }
                }
            }

            if (jaxpProperties != null) {            
                String propertyValue = jaxpProperties.getProperty(propertyName);
                if (propertyValue != null && propertyValue.length() >= 0) {
                    if (DEBUG) {
                        debugPrintln("found \"" + propertyName + "\" in jaxp.properties, value=" + propertyValue);
                    }
                    final int intValue = Integer.parseInt(propertyValue);
                    fLimitSpecified = true;
                    if (intValue > 0) {
                        return intValue;
                    }
                    // Treat 0 and negative numbers as no limit (i.e. max integer).
                    return Integer.MAX_VALUE;
                }
            }
        }
        // The VM ran out of memory or there was some other serious problem. Re-throw.
        catch (VirtualMachineError vme) {
            throw vme;
        }
        // ThreadDeath should always be re-thrown
        catch (ThreadDeath td) {
            throw td;
        }
        catch (Throwable e) {
            // Ignore all other exceptions/errors and return the default value.
            if (DEBUG) {
                debugPrintln(e.getClass().getName() + ": " + e.getMessage());
                e.printStackTrace();
            }
        }
        
        // Step #3: Return the default value.
        return defaultValue;
    }
    
    private String getPropertyValue(String propertyName, String defaultValue) {
        
        fLimitSpecified = false;
        
        // Step #1: Use the system property first
        try {
            String propertyValue = SecuritySupport.getSystemProperty(propertyName);
            if (propertyValue != null && propertyValue.length() >= 0) {
                if (DEBUG) {
                    debugPrintln("found system property \"" + propertyName + "\", value=" + propertyValue);
                }
                fLimitSpecified = true;
                return propertyValue;
            }
        }
        // The VM ran out of memory or there was some other serious problem. Re-throw.
        catch (VirtualMachineError vme) {
            throw vme;
        }
        // ThreadDeath should always be re-thrown
        catch (ThreadDeath td) {
            throw td;
        }
        catch (Throwable e) {
            // Ignore all other exceptions/errors and continue w/ next location
            if (DEBUG) {
                debugPrintln(e.getClass().getName() + ": " + e.getMessage());
                e.printStackTrace();
            }
        }
        
        // Step #2: Use $java.home/lib/jaxp.properties
        try {
            boolean fExists = false;
            File f = null;
            try {               
                String javah = SecuritySupport.getSystemProperty("java.home");
                String configFile = javah + File.separator +
                        "lib" + File.separator + "jaxp.properties";

                f = new File(configFile);
                fExists = SecuritySupport.getFileExists(f);

            }
            catch (SecurityException se) {
                // If there is a security exception, move on to next location.
                lastModified = -1;
                jaxpProperties = null;            
            }

            synchronized (SecureProcessingConfiguration.class) {    

                boolean runBlock = false;
                FileInputStream fis = null;

                try {
                    if (lastModified >= 0) {
                        // File has been modified, or didn't previously exist. 
                        // Need to reload properties    
                        if ((fExists) &&
                            (lastModified < (lastModified = SecuritySupport.getLastModified(f)))) {  
                            runBlock = true;
                        } 
                        else {
                            if (!fExists) {
                                // file existed, but it's been deleted.
                                lastModified = -1;
                                jaxpProperties = null;
                            }
                        }        
                    } 
                    else {
                        if (fExists) { 
                            // File didn't exist, but it does now.
                            runBlock = true;
                            lastModified = SecuritySupport.getLastModified(f);
                        }    
                    }

                    if (runBlock == true) {
                        // Try to read from $java.home/lib/jaxp.properties
                        jaxpProperties = new Properties();

                        fis = SecuritySupport.getFileInputStream(f);
                        jaxpProperties.load(fis);
                    }       

                }
                catch (Exception x) {
                    lastModified = -1;
                    jaxpProperties = null;
                    // assert(x instanceof FileNotFoundException
                    //        || x instanceof SecurityException)
                    // In both cases, ignore and return the default value
                }
                finally {
                    // try to close the input stream if one was opened.
                    if (fis != null) {
                        try {
                            fis.close();
                        }
                        // Ignore the exception.
                        catch (IOException exc) {}
                    }
                }
            }

            if (jaxpProperties != null) {            
                String propertyValue = jaxpProperties.getProperty(propertyName);
                if (propertyValue != null && propertyValue.length() >= 0) {
                    if (DEBUG) {
                        debugPrintln("found \"" + propertyName + "\" in jaxp.properties, value=" + propertyValue);
                    }
                    fLimitSpecified = true;
                    return propertyValue;
                }
            }
        }
        // The VM ran out of memory or there was some other serious problem. Re-throw.
        catch (VirtualMachineError vme) {
            throw vme;
        }
        // ThreadDeath should always be re-thrown
        catch (ThreadDeath td) {
            throw td;
        }
        catch (Throwable e) {
            // Ignore all other exceptions/errors and return the default value.
            if (DEBUG) {
                debugPrintln(e.getClass().getName() + ": " + e.getMessage());
                e.printStackTrace();
            }
        }
        
        // Step #3: Return the default value.
        return defaultValue;
    }
    
    private boolean getPropertyValue(String propertyName, boolean defaultValue) {
        
        fLimitSpecified = false;
        
        // Step #1: Use the system property first
        try {
            String propertyValue = SecuritySupport.getSystemProperty(propertyName);
            if (propertyValue != null && propertyValue.length() >= 0) {
                if (DEBUG) {
                    debugPrintln("found system property \"" + propertyName + "\", value=" + propertyValue);
                }
                final boolean booleanValue = Boolean.valueOf(propertyValue).booleanValue();
                fLimitSpecified = true;
                return booleanValue;
            }
        }
        // The VM ran out of memory or there was some other serious problem. Re-throw.
        catch (VirtualMachineError vme) {
            throw vme;
        }
        // ThreadDeath should always be re-thrown
        catch (ThreadDeath td) {
            throw td;
        }
        catch (Throwable e) {
            // Ignore all other exceptions/errors and continue w/ next location
            if (DEBUG) {
                debugPrintln(e.getClass().getName() + ": " + e.getMessage());
                e.printStackTrace();
            }
        }
        
        // Step #2: Use $java.home/lib/jaxp.properties
        try {
            boolean fExists = false;
            File f = null;
            try {               
                String javah = SecuritySupport.getSystemProperty("java.home");
                String configFile = javah + File.separator +
                        "lib" + File.separator + "jaxp.properties";

                f = new File(configFile);
                fExists = SecuritySupport.getFileExists(f);

            }
            catch (SecurityException se) {
                // If there is a security exception, move on to next location.
                lastModified = -1;
                jaxpProperties = null;            
            }

            synchronized (SecureProcessingConfiguration.class) {    

                boolean runBlock = false;
                FileInputStream fis = null;

                try {
                    if (lastModified >= 0) {
                        // File has been modified, or didn't previously exist. 
                        // Need to reload properties    
                        if ((fExists) &&
                            (lastModified < (lastModified = SecuritySupport.getLastModified(f)))) {  
                            runBlock = true;
                        } 
                        else {
                            if (!fExists) {
                                // file existed, but it's been deleted.
                                lastModified = -1;
                                jaxpProperties = null;
                            }
                        }        
                    } 
                    else {
                        if (fExists) { 
                            // File didn't exist, but it does now.
                            runBlock = true;
                            lastModified = SecuritySupport.getLastModified(f);
                        }    
                    }

                    if (runBlock == true) {
                        // Try to read from $java.home/lib/jaxp.properties
                        jaxpProperties = new Properties();

                        fis = SecuritySupport.getFileInputStream(f);
                        jaxpProperties.load(fis);
                    }       

                }
                catch (Exception x) {
                    lastModified = -1;
                    jaxpProperties = null;
                    // assert(x instanceof FileNotFoundException
                    //        || x instanceof SecurityException)
                    // In both cases, ignore and return the default value
                }
                finally {
                    // try to close the input stream if one was opened.
                    if (fis != null) {
                        try {
                            fis.close();
                        }
                        // Ignore the exception.
                        catch (IOException exc) {}
                    }
                }
            }

            if (jaxpProperties != null) {            
                String propertyValue = jaxpProperties.getProperty(propertyName);
                if (propertyValue != null && propertyValue.length() >= 0) {
                    if (DEBUG) {
                        debugPrintln("found \"" + propertyName + "\" in jaxp.properties, value=" + propertyValue);
                    }
                    final boolean booleanValue = Boolean.valueOf(propertyValue).booleanValue();
                    fLimitSpecified = true;
                    return booleanValue;
                }
            }
        }
        // The VM ran out of memory or there was some other serious problem. Re-throw.
        catch (VirtualMachineError vme) {
            throw vme;
        }
        // ThreadDeath should always be re-thrown
        catch (ThreadDeath td) {
            throw td;
        }
        catch (Throwable e) {
            // Ignore all other exceptions/errors and return the default value.
            if (DEBUG) {
                debugPrintln(e.getClass().getName() + ": " + e.getMessage());
                e.printStackTrace();
            }
        }
        
        // Step #3: Return the default value.
        return defaultValue;
    }
    
    //
    // Private static methods
    //
    
    /** Returns true if debug has been enabled. */
    private static boolean isDebugEnabled() {
        try {
            String val = SecuritySupport.getSystemProperty("xerces.debug");
            // Allow simply setting the prop to turn on debug
            return (val != null && (!"false".equals(val)));
        } 
        catch (SecurityException se) {}
        return false;
    } // isDebugEnabled()

    /** Prints a message to standard error if debugging is enabled. */
    private static void debugPrintln(String msg) {
        if (DEBUG) {
            System.err.println("XERCES: " + msg);
        }
    } // debugPrintln(String)
    
    /**
     * XMLDTDFilter which checks limits imposed by the application 
     * on the sizes of general and parameter entities.
     */
    final class InternalEntityMonitor implements XMLDTDFilter {
        
        /** DTD source and handler. **/
        private XMLDTDSource fDTDSource;
        private XMLDTDHandler fDTDHandler;
        
        public InternalEntityMonitor() {//System.out.println("InternalEntityMonitor()");
        }

        /*
         * XMLDTDHandler methods
         */

        public void startDTD(XMLLocator locator, Augmentations augmentations)
                throws XNIException {
            if (fDTDHandler != null) {
                fDTDHandler.startDTD(locator, augmentations);
            }
        }

        public void startParameterEntity(String name,
                XMLResourceIdentifier identifier, String encoding,
                Augmentations augmentations) throws XNIException {
            if (fDTDHandler != null) {
                fDTDHandler.startParameterEntity(name, identifier, encoding, augmentations);
            }
        }

        public void textDecl(String version, String encoding,
                Augmentations augmentations) throws XNIException {
            if (fDTDHandler != null) {
                fDTDHandler.textDecl(version, encoding, augmentations);
            }
        }

        public void endParameterEntity(String name, Augmentations augmentations)
                throws XNIException {
            if (fDTDHandler != null) {
                fDTDHandler.endParameterEntity(name, augmentations);
            }
        }

        public void startExternalSubset(XMLResourceIdentifier identifier,
                Augmentations augmentations) throws XNIException {
            if (fDTDHandler != null) {
                fDTDHandler.startExternalSubset(identifier, augmentations);
            }
        }

        public void endExternalSubset(Augmentations augmentations)
                throws XNIException {
            if (fDTDHandler != null) {
                fDTDHandler.endExternalSubset(augmentations);
            }
        }

        public void comment(XMLString text, Augmentations augmentations)
                throws XNIException {
            if (fDTDHandler != null) {
                fDTDHandler.comment(text, augmentations);
            }
        }

        public void processingInstruction(String target, XMLString data,
                Augmentations augmentations) throws XNIException {
            if (fDTDHandler != null) {
                fDTDHandler.processingInstruction(target, data, augmentations);
            }
        }

        public void elementDecl(String name, String contentModel,
                Augmentations augmentations) throws XNIException {
            if (fDTDHandler != null) {
                fDTDHandler.elementDecl(name, contentModel, augmentations);
            }
        }

        public void startAttlist(String elementName, Augmentations augmentations)
                throws XNIException {
            if (fDTDHandler != null) {
                fDTDHandler.startAttlist(elementName, augmentations);
            }
        }

        public void attributeDecl(String elementName, String attributeName,
                String type, String[] enumeration, String defaultType,
                XMLString defaultValue, XMLString nonNormalizedDefaultValue,
                Augmentations augmentations) throws XNIException {
            if (fDTDHandler != null) {
                fDTDHandler.attributeDecl(elementName, attributeName,
                        type, enumeration, defaultType,
                        defaultValue, nonNormalizedDefaultValue,
                        augmentations);
            }
        }

        public void endAttlist(Augmentations augmentations) throws XNIException {
            if (fDTDHandler != null) {
                fDTDHandler.endAttlist(augmentations);
            }
        }

        public void internalEntityDecl(String name, XMLString text,
                XMLString nonNormalizedText, Augmentations augmentations)
                throws XNIException {
            checkEntitySizeLimits(text.length, text.length, name != null && name.startsWith("%"));
            if (fDTDHandler != null) {
                fDTDHandler.internalEntityDecl(name, text,
                        nonNormalizedText, augmentations);
            }
        }

        public void externalEntityDecl(String name,
                XMLResourceIdentifier identifier, Augmentations augmentations)
                throws XNIException {
            if (fDTDHandler != null) {
                fDTDHandler.externalEntityDecl(name, identifier, augmentations);
            }
        }

        public void unparsedEntityDecl(String name,
                XMLResourceIdentifier identifier, String notation,
                Augmentations augmentations) throws XNIException {
            if (fDTDHandler != null) {
                fDTDHandler.unparsedEntityDecl(name, identifier, notation, augmentations);
            }
        }

        public void notationDecl(String name, XMLResourceIdentifier identifier,
                Augmentations augmentations) throws XNIException {
            if (fDTDHandler != null) {
                fDTDHandler.notationDecl(name, identifier, augmentations);
            }
        }

        public void startConditional(short type, Augmentations augmentations)
                throws XNIException {
            if (fDTDHandler != null) {
                fDTDHandler.startConditional(type, augmentations);
            }
        }

        public void ignoredCharacters(XMLString text, Augmentations augmentations)
                throws XNIException {
            if (fDTDHandler != null) {
                fDTDHandler.ignoredCharacters(text, augmentations);
            }

        }

        public void endConditional(Augmentations augmentations) throws XNIException {
            if (fDTDHandler != null) {
                fDTDHandler.endConditional(augmentations);
            }
        }

        public void endDTD(Augmentations augmentations) throws XNIException {
            if (fDTDHandler != null) {
                fDTDHandler.endDTD(augmentations);
            }
        }

        public void setDTDSource(XMLDTDSource source) {
            fDTDSource = source;
        }

        public XMLDTDSource getDTDSource() {
            return fDTDSource;
        }
        
        /*
         * XMLDTDSource methods
         */

        public void setDTDHandler(XMLDTDHandler handler) {
            fDTDHandler = handler;
        }

        public XMLDTDHandler getDTDHandler() {
            return fDTDHandler;
        }
    }
    
    /**
     * XMLEntityResolver which checks limits imposed by the application 
     * on the sizes of general and parameter entities.
     */
    final class ExternalEntityMonitor implements XMLEntityResolver {
        
        public ExternalEntityMonitor()
        {
            //System.out.println("ExternalEntityMonitor()");
        }
        /**
         * java.io.InputStream wrapper which check entity size limits.
         */
        final class InputStreamMonitor extends FilterInputStream {
            
            private final boolean isPE;
            private int size = 0;

            protected InputStreamMonitor(InputStream in, boolean isPE) {
                super(in);
                this.isPE = isPE;
            }
            
            public int read() throws IOException {
                int i = super.read();
                if (i != -1) {
                    ++size;
                    checkEntitySizeLimits(size, 1, isPE);
                }
                return i;
            }
            
            public int read(byte[] b, int off, int len) throws IOException {
                int i = super.read(b, off, len);
                if (i > 0) {
                    size += i;
                    checkEntitySizeLimits(size, i, isPE);
                }
                return i;
            }
        }
        
        /**
         * java.io.Reader wrapper which check entity size limits.
         */
        final class ReaderMonitor extends FilterReader {
            
            private final boolean isPE;
            private int size = 0;

            protected ReaderMonitor(Reader in, boolean isPE) {
                super(in);
                this.isPE = isPE;
            }
            
            public int read() throws IOException {
                int i = super.read();
                if (i != -1) {
                    ++size;
                    checkEntitySizeLimits(size, 1, isPE);
                }
                return i;
            }
            
            public int read(char[] cbuf, int off, int len) throws IOException {
                int i = super.read(cbuf, off, len);
                if (i > 0) {
                    size += i;
                    checkEntitySizeLimits(size, i, isPE);
                }
                return i;
            }
        }
        
        private XMLEntityResolver fEntityResolver;

        public XMLInputSource resolveEntity(XMLResourceIdentifier resourceIdentifier) throws XNIException,
                IOException {
            XMLInputSource source = null;
            if (fEntityResolver != null) {
                source = fEntityResolver.resolveEntity(resourceIdentifier);
            }
            if (fSecurityManager != null && resourceIdentifier instanceof XMLEntityDescription) {
                String name = ((XMLEntityDescription) resourceIdentifier).getEntityName();
                boolean isPE = name != null && name.startsWith("%");
                if (source == null) {
                    String publicId = resourceIdentifier.getPublicId();
                    String systemId = resourceIdentifier.getExpandedSystemId();
                    String baseSystemId = resourceIdentifier.getBaseSystemId();
                    source = new XMLInputSource(publicId, systemId, baseSystemId);
                }
                Reader reader = source.getCharacterStream();
                if (reader != null) {
                    source.setCharacterStream(new ReaderMonitor(reader, isPE));
                }
                else {
                    InputStream stream = source.getByteStream();
                    if (stream != null) {
                        source.setByteStream(new InputStreamMonitor(stream, isPE));
                    }
                    else {
                        String systemId = resourceIdentifier.getExpandedSystemId();
                        URL url = new URL(systemId);
                        stream = url.openStream();
                        source.setByteStream(new InputStreamMonitor(stream, isPE));
                    }
                }
            }
            return source;
        }
        
        /** Sets the XNI entity resolver. */
        public void setEntityResolver(XMLEntityResolver entityResolver) {
            fEntityResolver = entityResolver;
        } // setEntityResolver(XMLEntityResolver)

        /** Returns the XNI entity resolver. */
        public XMLEntityResolver getEntityResolver() {
            return fEntityResolver;
        } // getEntityResolver():XMLEntityResolver
    }  
}
