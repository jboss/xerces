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

package org.apache.xerces.util;

import java.io.IOException;
import java.net.URL;

import org.apache.xerces.impl.Constants;

/**
 * This class is a container for parser settings that relate to 
 * security, or more specifically, it is intended to be used to prevent denial-of-service 
 * attacks from being launched against a system running Xerces.  
 * Any component that is aware of a denial-of-service attack that can arise
 * from its processing of a certain kind of document may query its Component Manager
 * for the property (http://apache.org/xml/properties/security-manager) 
 * whose value will be an instance of this class.  
 * If no value has been set for the property, the component should proceed in the "usual" (spec-compliant)
 * manner.  If a value has been set, then it must be the case that the component in
 * question needs to know what method of this class to query.  This class
 * will provide defaults for all known security issues, but will also provide
 * setters so that those values can be tailored by applications that care.
 *
 * @author  Neil Graham, IBM
 *
 * @version $Id$
 */
public final class SecurityManager {

    //
    // Recognized properties
    //
    
    private final static String ACCESS_EXTERNAL_DTD_PROPERTY      = Constants.JAXP_JAVAX_PROPERTY_PREFIX  + Constants.ACCESS_EXTERNAL_DTD;
    private final static String ACCESS_EXTERNAL_SCHEMA_PROPERTY   = Constants.JAXP_JAVAX_PROPERTY_PREFIX  + Constants.ACCESS_EXTERNAL_SCHEMA;
    private final static String ELEMENT_ATTRIBUTE_LIMIT_PROPERTY  = Constants.XERCES_PROPERTY_PREFIX      + Constants.ELEMENT_ATTRIBUTE_LIMIT_PROPERTY;
    private static final String ELEMENT_ATTRIBUTE_LIMIT_PROPERTY2 = Constants.JAXP_ORACLE_PROPERTY_PREFIX + Constants.ELEMENT_ATTRIBUTE_LIMIT_PROPERTY;
    private final static String ENTITY_EXPANSION_LIMIT_PROPERTY   = Constants.XERCES_PROPERTY_PREFIX      + Constants.ENTITY_EXPANSION_LIMIT_PROPERTY;
    private final static String ENTITY_EXPANSION_LIMIT_PROPERTY2  = Constants.JAXP_ORACLE_PROPERTY_PREFIX + Constants.ENTITY_EXPANSION_LIMIT_PROPERTY2;
    private final static String MAX_ELEMENT_DEPTH_PROPERTY        = Constants.JAXP_PROPERTY_PREFIX        + Constants.MAX_ELEMENT_DEPTH;
    private final static String MAX_ELEMENT_DEPTH_PROPERTY2       = Constants.JAXP_ORACLE_PROPERTY_PREFIX + Constants.MAX_ELEMENT_DEPTH;
    private final static String MAX_OCCUR_LIMIT                   = Constants.JAXP_ORACLE_PROPERTY_PREFIX + Constants.MAX_OCCUR_LIMIT;
    private final static String MAX_GENERAL_ENTITY_SIZE_LIMIT     = Constants.JAXP_ORACLE_PROPERTY_PREFIX + Constants.MAX_GENERAL_ENTITY_SIZE_LIMIT;
    private final static String MAX_PARAMETER_ENTITY_SIZE_LIMIT   = Constants.JAXP_ORACLE_PROPERTY_PREFIX + Constants.MAX_PARAMETER_ENTITY_SIZE_LIMIT;
    private final static String MAX_TOTAL_ENTITY_SIZE_LIMIT       = Constants.JAXP_ORACLE_PROPERTY_PREFIX + Constants.MAX_TOTAL_ENTITY_SIZE_LIMIT;
    //
    // Constants
    //

    private static final String DEFAULT_ACCESS_EXTERNAL_DTD = "all";
    private static final String DEFAULT_ACCESS_EXTERNAL_SCHEMA = "all";
        
    /** Default value of number of attributes allowed. **/
    private final static int DEFAULT_ELEMENT_ATTRIBUTE_LIMIT = 10000;
    
    /** Default value for entity expansion limit. **/
    private final static int DEFAULT_ENTITY_EXPANSION_LIMIT = 100000;
    
    /** Default value of maximum element depth. **/
    private final static int DEFAULT_MAX_ELEMENT_DEPTH = Integer.MAX_VALUE; 
    
    /** Default value of number of nodes created. **/
    private final static int DEFAULT_MAX_OCCUR_NODE_LIMIT = 3000;  
    
    private static final int DEFAULT_MAX_GENERAL_ENTITY_SIZE_LIMIT = Integer.MAX_VALUE;
    private static final int DEFAULT_MAX_PARAMETER_ENTITY_SIZE_LIMIT = 1000000;
    private static final int DEFAULT_TOTAL_ENTITY_SIZE_LIMIT = 50000000;

    //
    // Data
    //
    
    private String accessExternalDTD = DEFAULT_ACCESS_EXTERNAL_DTD;
    
    private String accessExternalSchema = DEFAULT_ACCESS_EXTERNAL_SCHEMA;
        
    private int elementAttributeLimit = DEFAULT_ELEMENT_ATTRIBUTE_LIMIT;
    
    /** Entity expansion limit. **/
    private int entityExpansionLimit = DEFAULT_ENTITY_EXPANSION_LIMIT;
        
    private int maxElementDepth = DEFAULT_MAX_ELEMENT_DEPTH;
    
    /** W3C XML Schema maxOccurs limit. **/
    private int maxOccurLimit = DEFAULT_MAX_OCCUR_NODE_LIMIT;
    
    private int generalEntitySizeLimit = DEFAULT_MAX_GENERAL_ENTITY_SIZE_LIMIT;
    
    private int parameterEntitySizeLimit = DEFAULT_MAX_PARAMETER_ENTITY_SIZE_LIMIT;
        
    private int totalEntitySizeLimit = DEFAULT_TOTAL_ENTITY_SIZE_LIMIT;

    /**
     * Default constructor.
     */  
    public SecurityManager() {
    }
    
    public String getAccessExternalDTD() {
        return accessExternalDTD;
    }

    public void setAccessExternalDTD(String accessExternalDTD) {
        this.accessExternalDTD = accessExternalDTD;
    }

    public String getAccessExternalSchema() {
        return accessExternalSchema;
    }

    public void setAccessExternalSchema(String accessExternalSchema) {
        this.accessExternalSchema = accessExternalSchema;
    }
         
    public int getElementAttributeLimit() {
        return elementAttributeLimit;
    }
       
    public void setElementAttributeLimit(int limit) {  
        if (limit > 0)
        {
            elementAttributeLimit = limit;
        }
        else if (limit == 0)
        {
            elementAttributeLimit = Integer.MAX_VALUE;
        }
        else
        {
            elementAttributeLimit = 0;
        }
    }
    
    /**
     * <p>Returns the number of entity expansions 
     * that the parser permits in a document.</p>
     *
     * @return the number of entity expansions
     * permitted in a document
     */
    public int getEntityExpansionLimit() {
        return entityExpansionLimit;
    }
    
    /**
     * <p>Sets the number of entity expansions that the
     * parser should permit in a document.</p>
     *
     * @param limit the number of entity expansions
     * permitted in a document
     */
    public void setEntityExpansionLimit(int limit) {
        if (limit > 0)
        {
            entityExpansionLimit = limit;
        }
        else if (limit == 0)
        {
            entityExpansionLimit = Integer.MAX_VALUE;
        }
        else
        {
            entityExpansionLimit = 0;
        }
    }
    
    public int getMaxElementDepth() {
        return maxElementDepth;
    }

    public void setMaxElementDepth(int limit) {
        if (limit > 0)
        {
            maxElementDepth = limit;
        }
        else if (limit == 0)
        {
            maxElementDepth = Integer.MAX_VALUE;
        }
        else
        {
            maxElementDepth = 0;
        } 
    }
        
    /**
     * <p>Returns the limit of the number of content model nodes 
     * that may be created when building a grammar for a W3C 
     * XML Schema that contains maxOccurs attributes with values
     * other than "unbounded".</p>
     *
     * @return the maximum value for maxOccurs other
     * than "unbounded"
     */ 
    public int getMaxOccurNodeLimit(){
        return maxOccurLimit;    
    }
    
    /**
     * <p>Sets the limit of the number of content model nodes 
     * that may be created when building a grammar for a W3C 
     * XML Schema that contains maxOccurs attributes with values
     * other than "unbounded".</p>
     *
     * @param limit the maximum value for maxOccurs other
     * than "unbounded"
     */
    public void setMaxOccurNodeLimit(int limit){
        if (limit > 0)
        {
            maxOccurLimit = limit;
        }
        else if (limit == 0)
        {
            maxOccurLimit = Integer.MAX_VALUE;
        }
        else
        {
            maxOccurLimit = 0;
        } 
    }

    public int getGeneralEntitySizeLimit() {
        return generalEntitySizeLimit;
    }

    public void setGeneralEntitySizeLimit(int limit) {
        if (limit > 0)
        {
            generalEntitySizeLimit = limit;
        }
        else if (limit == 0)
        {
            generalEntitySizeLimit = Integer.MAX_VALUE;
        }
        else
        {
            generalEntitySizeLimit = 0;
        }  
    }

    public int getParameterEntitySizeLimit() {
        return parameterEntitySizeLimit;
    }

    public void setParameterEntitySizeLimit(int limit) {
        if (limit > 0)
        {
            parameterEntitySizeLimit = limit;
        }
        else if (limit == 0)
        {
            parameterEntitySizeLimit = Integer.MAX_VALUE;
        }
        else
        {
            parameterEntitySizeLimit = 0;
        } 
    }
    
    public int getTotalEntitySizeLimit() {
        return totalEntitySizeLimit;
    }

    public void setTotalEntitySizeLimit(int limit) {
        if (limit > 0)
        {
            totalEntitySizeLimit = limit;
        }
        else if (limit == 0)
        {
            totalEntitySizeLimit = Integer.MAX_VALUE;
        }
        else
        {
            totalEntitySizeLimit = 0;
        }
    }
    
    public boolean setIfManagedBySecurityManager(String property, Object value)
    {
        boolean isManaged = false;
        if (ACCESS_EXTERNAL_DTD_PROPERTY.equals(property))
        {
            setAccessExternalDTD(String.class.cast(value));
            isManaged = true;
        }
        else if (ACCESS_EXTERNAL_SCHEMA_PROPERTY.equals(property))
        {
            setAccessExternalSchema(String.class.cast(value));
            isManaged = true;
        }
        else if (ELEMENT_ATTRIBUTE_LIMIT_PROPERTY.equals(property) || ELEMENT_ATTRIBUTE_LIMIT_PROPERTY2.equals(property))
        {
            setElementAttributeLimit(Integer.class.cast(value));
            isManaged = true;
        }
        else if (ENTITY_EXPANSION_LIMIT_PROPERTY.equals(property) || ENTITY_EXPANSION_LIMIT_PROPERTY2.equals(property))
        {
            setEntityExpansionLimit(Integer.class.cast(value));
            isManaged = true;
        }
        else if (MAX_ELEMENT_DEPTH_PROPERTY.equals(property) || MAX_ELEMENT_DEPTH_PROPERTY2.equals(property))
        {
            setMaxElementDepth(Integer.class.cast(value));
            isManaged = true;
        }
        else if (MAX_OCCUR_LIMIT.equals(property))
        {
            setMaxOccurNodeLimit(Integer.class.cast(value));
            isManaged = true;
        }
        else if (MAX_GENERAL_ENTITY_SIZE_LIMIT.equals(property))
        {
            setGeneralEntitySizeLimit(Integer.class.cast(value));
            isManaged = true;
        }
        else if (MAX_PARAMETER_ENTITY_SIZE_LIMIT.equals(property))
        {
            setParameterEntitySizeLimit(Integer.class.cast(value));
            isManaged = true;
        }
        else if (MAX_TOTAL_ENTITY_SIZE_LIMIT.equals(property))
        {
            setTotalEntitySizeLimit(Integer.class.cast(value));
            isManaged = true;
        }
        return isManaged;
    }
    
    public Object getIfManagedBySecurityManager(String property)
    {
        if (ACCESS_EXTERNAL_DTD_PROPERTY.equals(property))
        {
            return getAccessExternalDTD();
        }
        else if (ACCESS_EXTERNAL_SCHEMA_PROPERTY.equals(property))
        {
            return getAccessExternalSchema();
        }
        else if (ELEMENT_ATTRIBUTE_LIMIT_PROPERTY.equals(property) || ELEMENT_ATTRIBUTE_LIMIT_PROPERTY2.equals(property))
        {
            return getElementAttributeLimit();
        }
        else if (ENTITY_EXPANSION_LIMIT_PROPERTY.equals(property) || ENTITY_EXPANSION_LIMIT_PROPERTY2.equals(property))
        {
            return getEntityExpansionLimit();
        }
        else if (MAX_ELEMENT_DEPTH_PROPERTY.equals(property) || MAX_ELEMENT_DEPTH_PROPERTY2.equals(property))
        {
            return getMaxElementDepth();
        }
        else if (MAX_OCCUR_LIMIT.equals(property))
        {
            return getMaxOccurNodeLimit();
        }
        else if (MAX_GENERAL_ENTITY_SIZE_LIMIT.equals(property))
        {
            return getGeneralEntitySizeLimit();
        }
        else if (MAX_PARAMETER_ENTITY_SIZE_LIMIT.equals(property))
        {
            return getParameterEntitySizeLimit();
        }
        else if (MAX_TOTAL_ENTITY_SIZE_LIMIT.equals(property))
        {
            return getTotalEntitySizeLimit();
        }
        return null;
    }
    
    /**
     * Check the protocol used in the systemId against allowed protocols
     *
     * @param systemId the Id of the URI
     * @param allowedProtocols a list of allowed protocols separated by comma
     * @param accessAny keyword to indicate allowing any protocol
     * @return the name of the protocol if rejected, null otherwise
     */
    public static String checkAccess(String systemId, String allowedProtocols, String accessAny) throws IOException {
        if (systemId == null || (allowedProtocols != null &&
                allowedProtocols.equalsIgnoreCase(accessAny))) {
            return null;
        }

        String protocol;
        if (systemId.indexOf(":")==-1) {
            protocol = "file";
        } else {
            URL url = new URL(systemId);
            protocol = url.getProtocol();
            if (protocol.equalsIgnoreCase("jar")) {
                String path = url.getPath();
                protocol = path.substring(0, path.indexOf(":"));
            }
        }

        if (isProtocolAllowed(protocol, allowedProtocols)) {
            //access allowed
            return null;
        } else {
            return protocol;
        }
    }
    
    /**
     * Check if the protocol is in the allowed list of protocols. The check
     * is case-insensitive while ignoring whitespaces.
     *
     * @param protocol a protocol
     * @param allowedProtocols a list of allowed protocols
     * @return true if the protocol is in the list
     */
    private static boolean isProtocolAllowed(String protocol, String allowedProtocols) {
         if (allowedProtocols == null) {
             return false;
         }
         String temp[] = allowedProtocols.split(",");
         for (String t : temp) {
             t = t.trim();
             if (t.equalsIgnoreCase(protocol)) {
                 return true;
             }
         }
         return false;
     }
    
} // class SecurityManager

