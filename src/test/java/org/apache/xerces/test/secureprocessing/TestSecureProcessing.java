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

package org.apache.xerces.test.secureprocessing;

import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import junit.framework.Assert;

import org.apache.xerces.impl.Constants;
import org.apache.xerces.jaxp.DocumentBuilderImpl;
import org.apache.xerces.jaxp.JAXPConstants;
import org.apache.xerces.util.SecurityManager;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.Attributes;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;


/**
 * 
 * namespaces:  false
 * validating:  false
 * xml version: 1.0
 * 
 * The following Features and Properties are tested in the named test methods.
 * 
 * FEATURES:
 * 
 *  * DISALLOW_DOCTYPE_DECL_FEATURE       (http://apache.org/xml/features/disallow-doctype-decl):           testDisallowDoctype()
 *  * EXTERNAL_GENERAL_ENTITIES_FEATURE   (http://xml.org/sax/features/external-general-entities):          testExternalEntities()
 *  * EXTERNAL_PARAMETER_ENTITIES_FEATURE (http://xml.org/sax/features/external-parameter-entities):        testExternalEntities()
 *  * LOAD_EXTERNAL_DTD_FEATURE           (http://apache.org/xml/features/nonvalidating/load-external-dtd): testExternalDTD()
 *  
 * PROPERTIES:
 * 
 *  * ACCESS_EXTERNAL_DTD_PROPERTY    (http://javax.xml.XMLConstants/property/accessExternalDTD):              testExternalDTD()
 *  * ACCESS_EXTERNAL_SCHEMA_PROPERTY (http://javax.xml.XMLConstants/property/accessExternalSchema):           testExternalSchema()
 *  * ELEMENT_ATTRIBUTE_LIMIT         (http://apache.org/xml/properties/elementAttributeLimit):                testElementAttributeLimit()
 *  * ENTITY_EXPANSION_LIMIT          (http://apache.org/xml/properties/entity-expansion-limit):               testEntityExpansionLimit()
 *  * MAX_OCCUR_LIMIT                 (http://www.oracle.com/xml/jaxp/properties/maxOccurLimit):               testMaxOccursSchema(), testMaxOccurs()
 *  * MAX_GENERAL_ENTITY_SIZE_LIMIT   (http://www.oracle.com/xml/jaxp/properties/maxGeneralEntitySizeLimit):   testEntitySizeLimit()
 *  * MAX_GENERAL_ENTITY_SIZE_LIMIT2  (http://java.sun.com/xml/jaxp/properties/maxGeneralEntitySizeLimit:      testEntitySizeLimit()
 *  * MAX_PARAMETER_ENTITY_SIZE_LIMIT (http://www.oracle.com/xml/jaxp/properties/maxParameterEntitySizeLimit): testEntitySizeLimit()
 *  * MAX_ELEMENT_DEPTH               (http://java.sun.com/xml/jaxp/properties/maxElementDepth):               testElementDepthLimit()
 *  * MAX_TOTAL_ENTITY_SIZE_LIMIT     (http://www.oracle.com/xml/jaxp/properties/totalEntitySizeLimit):        testTotalEntitySizeLimit()
 *
 * Note. In the following tests, -1 is interpreted as "use default value".
 * 
 * @author <a href="mailto:ron.sigal@jboss.com">Ron Sigal</a>
 * @date November 24, 2014
 *
 */
public class TestSecureProcessing
{
    protected static final String SECURITY_MANAGER_PROPERTY = Constants.XERCES_PROPERTY_PREFIX + Constants.SECURITY_MANAGER_PROPERTY;
    
    protected static final String DISALLOW_DOCTYPE_DECL_FEATURE = Constants.XERCES_FEATURE_PREFIX + Constants.DISALLOW_DOCTYPE_DECL_FEATURE;
    protected static final String EXTERNAL_GENERAL_ENTITIES_FEATURE = "http://xml.org/sax/features/external-general-entities";
    protected static final String EXTERNAL_PARAMETER_ENTITIES_FEATURE = "http://xml.org/sax/features/external-parameter-entities";
    protected static final String LOAD_EXTERNAL_DTD_FEATURE = Constants.XERCES_FEATURE_PREFIX + Constants.LOAD_EXTERNAL_DTD_FEATURE;
    
    protected static final String ACCESS_EXTERNAL_DTD_PROPERTY = Constants.JAXP_JAVAX_PROPERTY_PREFIX + Constants.ACCESS_EXTERNAL_DTD;
    protected static final String ACCESS_EXTERNAL_SCHEMA_PROPERTY = Constants.JAXP_JAVAX_PROPERTY_PREFIX + Constants.ACCESS_EXTERNAL_SCHEMA;
    protected static final String MAX_OCCUR_LIMIT = Constants.JAXP_ORACLE_PROPERTY_PREFIX + Constants.MAX_OCCUR_LIMIT;
    protected static final String MAX_GENERAL_ENTITY_SIZE_LIMIT    = Constants.JAXP_ORACLE_PROPERTY_PREFIX + Constants.MAX_GENERAL_ENTITY_SIZE_LIMIT;
    protected static final String MAX_GENERAL_ENTITY_SIZE_LIMIT2   = Constants.JAXP_PROPERTY_PREFIX        + Constants.MAX_GENERAL_ENTITY_SIZE_LIMIT;
    protected static final String MAX_PARAMETER_ENTITY_SIZE_LIMIT  = Constants.JAXP_ORACLE_PROPERTY_PREFIX + Constants.MAX_PARAMETER_ENTITY_SIZE_LIMIT;
    protected static final String MAX_TOTAL_ENTITY_SIZE_LIMIT      = Constants.JAXP_ORACLE_PROPERTY_PREFIX + Constants.MAX_TOTAL_ENTITY_SIZE_LIMIT;
    
    /** Property identifier: schema location. */
    protected static final String SCHEMA_LOCATION = Constants.XERCES_PROPERTY_PREFIX + Constants.SCHEMA_LOCATION;

    /** Property identifier: no namespace schema location. */
    protected static final String SCHEMA_NONS_LOCATION = Constants.XERCES_PROPERTY_PREFIX + Constants.SCHEMA_NONS_LOCATION;
    
    protected static final String RESOLVE_EXTERNAL_ENTITIES_PROPERTY_NAME = "jdk.xml.resolveExternalEntities";
    protected static final String ENTITY_EXPANSION_LIMIT_PROPERTY_NAME = "jdk.xml.entityExpansionLimit";
    protected static final String ELEMENT_ATTRIBUTE_LIMIT_PROPERTY_NAME = "jdk.xml.elementAttributeLimit";
    protected static final String MAX_OCCUR_LIMIT_PROPERTY_NAME = "jdk.xml.maxOccur";
    protected static final String TOTAL_ENTITY_SIZE_LIMIT_PROPERTY_NAME = "jdk.xml.totalEntitySizeLimit";
    protected static final String MAX_GENERAL_ENTITY_SIZE_LIMIT_PROPERTY_NAME = "jdk.xml.maxGeneralEntitySizeLimit";
    protected static final String MAX_PARAMETER_ENTITY_SIZE_LIMIT_PROPERTY_NAME = "jdk.xml.maxParameterEntitySizeLimit";
    protected static final String MAX_ELEMENT_DEPTH_PROPERTY_NAME = "jdk.xml.maxElementDepth";
    protected static final String ACCESS_EXTERNAL_SCHEMA_PROPERTY_NAME = "javax.xml.accessExternalSchema";
    protected static final String ACCESS_EXTERNAL_DTD_PROPERTY_NAME = "javax.xml.accessExternalDTD";
    
    /** Feature identifier: namespaces. */
    protected static final String NAMESPACES = Constants.SAX_FEATURE_PREFIX + Constants.NAMESPACES_FEATURE;
    
    protected static String currentDirectory = System.getProperty("user.dir");
    protected static String file;
    protected static StringBuffer sb;
    
    protected boolean namespaces()
    {
        return false;
    }
    
    protected String XMLVersion()
    {
        return "<?xml version=\"1.0\"?>\r";
    }
    
    protected boolean validating()
    {
        return false;
    }
    
    protected String getElementAttributeLimitProperty()
    {
        return Constants.JAXP_ORACLE_PROPERTY_PREFIX + Constants.ELEMENT_ATTRIBUTE_LIMIT_PROPERTY;
    }
    
    protected String getEntityExpansionLimitProperty()
    {
        return Constants.JAXP_ORACLE_PROPERTY_PREFIX + Constants.ENTITY_EXPANSION_LIMIT_PROPERTY2;
    }
    
    protected String getMaxElementDepthProperty()
    {
        return Constants.JAXP_ORACLE_PROPERTY_PREFIX + Constants.MAX_ELEMENT_DEPTH;
    }
    
    protected String getExternalGeneralEntityDoc()
    {
        String externalGeneralEntityDoc = 
                XMLVersion() +
                "<!DOCTYPE externalGeneralEntity " +
                "[<!ENTITY externalGeneralEntity SYSTEM \"file://" + currentDirectory + "/src/test/java/org/apache/xerces/test/secureprocessing/external.text\">" +
                " <!ELEMENT externalGeneralEntity ANY>" +
                "]>" +
                "<externalGeneralEntity>&externalGeneralEntity;</externalGeneralEntity>";
        return externalGeneralEntityDoc;
    }
    
    protected String getExternalParameterEntityDoc()
    {
        String externalParameterEntityDoc = 
                XMLVersion() +
                "<!DOCTYPE externalParameterEntity " +
                "[<!ENTITY % externalParameterEntity SYSTEM \"file://" + currentDirectory + "/src/test/java/org/apache/xerces/test/secureprocessing/externalParameterEntity.dtd\">" + 
                " %externalParameterEntity;" +
                "]>" +
                "<externalParameterEntity>&foo;</externalParameterEntity>";
        return externalParameterEntityDoc;
    }
    
    protected String getInternalDTDDoc()
    {
        String internalDTDDoc = 
                XMLVersion() +
                "<!DOCTYPE internalDTDDoc [" + 
                   "<!ENTITY foo '0123456789'>" +
                   "<!ELEMENT internalDTDDoc ANY>" +
                "]>" + 
                "<internalDTDDoc>&foo;</internalDTDDoc>";
        return internalDTDDoc;
    }
    
    protected String getBigElementDoctype()
    {
        String bigElementDoctype =
                XMLVersion() +
                "<!DOCTYPE tag [" +
                      "<!ENTITY foo 'foo'>" +
                      "<!ENTITY foo1 '&foo;&foo;&foo;&foo;&foo;&foo;&foo;&foo;&foo;&foo;'>" +
                      "<!ENTITY foo2 '&foo1;&foo1;&foo1;&foo1;&foo1;&foo1;&foo1;&foo1;&foo1;&foo1;'>" +
                      "<!ENTITY foo3 '&foo2;&foo2;&foo2;&foo2;&foo2;&foo2;&foo2;&foo2;&foo2;&foo2;'>" +
                      "<!ENTITY foo4 '&foo3;&foo3;&foo3;&foo3;&foo3;&foo3;&foo3;&foo3;&foo3;&foo3;'>" +
                      "<!ENTITY foo5 '&foo4;&foo4;&foo4;&foo4;&foo4;&foo4;&foo4;&foo4;&foo4;&foo4;'>" +
                      "<!ENTITY foo6 '&foo5;&foo5;&foo5;&foo5;&foo5;&foo5;&foo5;&foo5;&foo5;&foo5;'>" +
                      "<!ELEMENT tag (subtag)>" +
                      "<!ELEMENT subtag (#PCDATA)>" +
                      "]>";
        String bigXmlRootElement = bigElementDoctype + "<tag><subtag>&foo5;</subtag></tag>";
        return bigXmlRootElement;
    }
    
    protected String bigAttributeDoc;
    protected String reallyBigAttributeDoc;
    
    protected String getBigAttributeDoc()
    {
        if (bigAttributeDoc == null)
        {
            StringBuffer sb = new StringBuffer();
            sb.append("<bar ");
            for (int i = 0; i < 100; i++)
            {
                sb.append("attr" + i + "=\"x\" ");  
            }
            sb.append("/>");
            bigAttributeDoc = sb.toString();
        }
        return bigAttributeDoc;
    }
    
    protected String getReallyBigAttributeDoc()
    {
        if (reallyBigAttributeDoc == null)
        {
            StringBuffer sb = new StringBuffer();
            sb.append("<bar ");
            for (int i = 0; i < 10002; i++)
            {
                sb.append("attr" + i + "=\"x\" ");  
            }
            sb.append("/>");
            reallyBigAttributeDoc = sb.toString();
        }
        return reallyBigAttributeDoc;
    }
    
    protected String getMaxOccursDoc()
    {
        file = System.getProperty("user.dir") + "/src/test/java/org/apache/xerces/test/secureprocessing/test.xsd";
        sb = new StringBuffer();
        sb.append(XMLVersion());
        sb.append("<foo xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xsi:noNamespaceSchemaLocation=\"" + file + "\">");
        for (int i = 0; i < 9999; i++)
        {
           sb.append("<bar>x</bar>");  
        }
        sb.append("</foo>");
        String maxOccursDoc = sb.toString();
        return maxOccursDoc;
    }
    
    protected String getExternalDTDWithInternalDTDDoc()
    {
        String externalDTDWithInternalDTDDoc = 
                XMLVersion() +
                "<!DOCTYPE foo SYSTEM \"file://" + currentDirectory + "/src/test/java/org/apache/xerces/test/secureprocessing/external.dtd\"[" + 
                "]>" +
                "<foo>&foo;</foo>";
        return externalDTDWithInternalDTDDoc;
    }

    protected String getExternalDTDWithoutInternalDTDDoc()
    {
        String externalDTDWithoutInternalDTDDoc = 
                XMLVersion() +
                "<!DOCTYPE foo SYSTEM \"file://" + currentDirectory + "/src/test/java/org/apache/xerces/test/secureprocessing/external.dtd\"" + 
                ">" +
                "<foo>&foo;</foo>";
        return externalDTDWithoutInternalDTDDoc;
    }
    
    protected String getExternalSchemaDoc()
    {
        String file = System.getProperty("user.dir") + "/src/test/java/org/apache/xerces/test/secureprocessing/foo.xsd";
        StringBuffer sb = new StringBuffer();
        sb.append(XMLVersion());
        sb.append("<foo xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xsi:noNamespaceSchemaLocation=\"" + file + "\">");
        sb.append("<bar>x</bar>");  
        sb.append("</foo>");
        String externalSchemaDoc = sb.toString();
        return externalSchemaDoc;
    }

    protected String getTotalEntitySizeDoc()
    {
        String totalEntitySizeDoc =
                XMLVersion() +
                "<!DOCTYPE totalEntitySizeDoc ["
                + "<!ENTITY foo1 '13'>"
                + "<!ENTITY foo2 '35'>"
                + "<!ENTITY foo3 '57'>"
                + "<!ENTITY foo4 '79'>"
                + "<!ELEMENT totalEntitySizeDoc EMPTY>"
                + "]> <totalEntitySizeDoc/>";
        return totalEntitySizeDoc;
    }
    
    protected String getGeneralEntitySizeDoc()
    {
        String generalEntitySizeDoc = 
                XMLVersion() +
                "<!DOCTYPE generalEntitySizeDoc ["
                + "<!ENTITY foo '12345678'>"
                + "<!ELEMENT generalEntitySizeDoc EMPTY>"
                + "]> <generalEntitySizeDoc/>";
        return generalEntitySizeDoc;
    }
 
    protected String getParameterEntitySizeDoc()
    {
        String parameterEntitySizeDoc = 
                XMLVersion() +
                "<!DOCTYPE parameterEntitySizeDoc ["
                + "<!ENTITY % foo '12345678'>"
                + "<!ELEMENT parameterEntitySizeDoc EMPTY>"
                + "]> <parameterEntitySizeDoc/>";
        return parameterEntitySizeDoc;
    }

    protected String getMaxElementDepthDoc()
    {
        String maxElementDepthDoc = 
                XMLVersion() +
                "<ent0>\r" +
                   "<ent1>\r" +
                      "<ent2>\r" +
                         "<ent3>\r" +
                            "<ent4>\r" +
                            "</ent4>\r" +
                         "</ent3>\r" +
                      "</ent2>\r" +
                   "</ent1>\r" +
                "</ent0>";
        return maxElementDepthDoc;
    }
       
    protected enum E 
    {
        TRUE(true),
        FALSE(false),
        DEFAULT(null);
        
        private Boolean b;
        
        E(Boolean b)
        {
            this.b = b;
        }
        
        public String toString()
        {
            return b.toString();
        }
        
        public Boolean bool()
        {
            return b;
        }
    }
    
    protected enum ParserType
    {
        SAX, DOM;
    }
    
    protected enum EntityType
    {
        GENERAL("general"),
        PARAMETER("parameter");
        
        private String entityType;
        
        EntityType(String entityType)
        {
            this.entityType = entityType;
        }
        
        public String toString()
        {
            return entityType;
        }
    }
    
    static protected boolean debug = false;
    
    @BeforeClass
    static public void before()
    {
        debug = Boolean.getBoolean("debug");
        System.out.println("debug: " + (debug ? "on" : "off"));
    }
    
    public void debug(Object s)
    {
        if (debug)
        {
            System.out.println(s.toString());
        }
    }
    
    
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    //  External general and parameter entity features:
    //
    //  * http://xml.org/sax/features/external-general-entities
    //  * http://xml.org/sax/features/external-parameter-entities
    //
    ////////////////////////////////////////////////////////////////////////////////////////////////////   
    
    @Test
    public void testExternalEntities() throws Exception
    {
        // Notes.
        //
        // 1. If the SECURE_PROCESSING_FEATURE is set to true
        //
        //    a. If RESOLVE_EXTERNAL_ENTITIES_PROPERTY_NAME (jdk.xml.resolveExternalEntities) is true, then
        //       the features EXTERNAL_GENERAL_ENTITIES and EXTERNAL_PARAMETER_ENTITIES are set to true.
        //
        //    b. If RESOLVE_EXTERNAL_ENTITIES_PROPERTY_NAME (jdk.xml.resolveExternalEntities) is false, then
        //       the features EXTERNAL_GENERAL_ENTITIES and EXTERNAL_PARAMETER_ENTITIES are set to false.
        //
        //    c. if RESOLVE_EXTERNAL_ENTITIES_PROPERTY_NAME is not set, the features EXTERNAL_GENERAL_ENTITIES
        //       and EXTERNAL_PARAMETER_ENTITIES default to false.
        //
        // 2. If the SECURE_PROCESSING_FEATURE is set to false, RESOLVE_EXTERNAL_ENTITIES_PROPERTY_NAME
        //    is ignored, and the features EXTERNAL_GENERAL_ENTITIES and EXTERNAL_PARAMETER_ENTITIES
        //    default to true.
        //    
        // 3. If the features EXTERNAL_GENERAL_ENTITIES or EXTERNAL_PARAMETER_ENTITIES are passed to the 
        //    SAX parser or the DOM parser factory, that value takes precedence over the values set according
        //    to items 1 and 2.
        
        doTestExternalEntities(ParserType.SAX, EntityType.GENERAL);
        doTestExternalEntities(ParserType.DOM, EntityType.GENERAL);
        doTestExternalEntities(ParserType.SAX, EntityType.PARAMETER);
        doTestExternalEntities(ParserType.DOM, EntityType.PARAMETER);
    }
    
    void doTestExternalEntities(ParserType type, EntityType entityType) throws Exception
    {   
//                                               jdk.xml.resolveExternalEntities
//                                               |          secure processing feature
//                                               |          |          load external entity feature
//                                               |          |          |          expected value
        doTestExternalEntities(type, entityType, E.TRUE,    E.TRUE,    E.TRUE,    "external " + entityType + " entity");
        doTestExternalEntities(type, entityType, E.TRUE,    E.TRUE,    E.FALSE,   "");
        doTestExternalEntities(type, entityType, E.TRUE,    E.TRUE,    E.DEFAULT, "external " + entityType + " entity");
        doTestExternalEntities(type, entityType, E.TRUE,    E.FALSE,   E.TRUE,    "external " + entityType + " entity");
        doTestExternalEntities(type, entityType, E.TRUE,    E.FALSE,   E.FALSE,   "");
        doTestExternalEntities(type, entityType, E.TRUE,    E.FALSE,   E.DEFAULT, "external " + entityType + " entity");
        doTestExternalEntities(type, entityType, E.TRUE,    E.DEFAULT, E.TRUE,    "external " + entityType + " entity");
        doTestExternalEntities(type, entityType, E.TRUE,    E.DEFAULT, E.FALSE,   "");
        doTestExternalEntities(type, entityType, E.TRUE,    E.DEFAULT, E.DEFAULT, "external " + entityType + " entity");
        
        doTestExternalEntities(type, entityType, E.FALSE,   E.TRUE,    E.TRUE,    "external " + entityType + " entity");
        doTestExternalEntities(type, entityType, E.FALSE,   E.TRUE,    E.FALSE,   "");
        doTestExternalEntities(type, entityType, E.FALSE,   E.TRUE,    E.DEFAULT, "");
        doTestExternalEntities(type, entityType, E.FALSE,   E.FALSE,   E.TRUE,    "external " + entityType + " entity");
        doTestExternalEntities(type, entityType, E.FALSE,   E.FALSE,   E.FALSE,   "");
        doTestExternalEntities(type, entityType, E.FALSE,   E.FALSE,   E.DEFAULT, "external " + entityType + " entity");
        doTestExternalEntities(type, entityType, E.FALSE,   E.DEFAULT, E.TRUE,    "external " + entityType + " entity");
        doTestExternalEntities(type, entityType, E.FALSE,   E.DEFAULT, E.FALSE,   "");
        doTestExternalEntities(type, entityType, E.FALSE,   E.DEFAULT, E.DEFAULT, "");
        
        doTestExternalEntities(type, entityType, E.DEFAULT, E.TRUE,    E.TRUE,    "external " + entityType + " entity");
        doTestExternalEntities(type, entityType, E.DEFAULT, E.TRUE,    E.FALSE,   "");
        doTestExternalEntities(type, entityType, E.DEFAULT, E.TRUE,    E.DEFAULT, "");
        doTestExternalEntities(type, entityType, E.DEFAULT, E.FALSE,   E.TRUE,    "external " + entityType + " entity");
        doTestExternalEntities(type, entityType, E.DEFAULT, E.FALSE,   E.FALSE,   "");
        doTestExternalEntities(type, entityType, E.DEFAULT, E.FALSE,   E.DEFAULT, "external " + entityType + " entity");
        doTestExternalEntities(type, entityType, E.DEFAULT, E.DEFAULT, E.TRUE,    "external " + entityType + " entity");
        doTestExternalEntities(type, entityType, E.DEFAULT, E.DEFAULT, E.FALSE,   "");
        doTestExternalEntities(type, entityType, E.DEFAULT, E.DEFAULT, E.DEFAULT, "");
    }
    
    void doTestExternalEntities(ParserType type, EntityType entityType, E systemProperty, E secureProcessing, E externalParameterEntities, String expected) throws Exception
    {
        try
        {
            String result = doTestExternalEntitiesParse(type, entityType, systemProperty, secureProcessing, externalParameterEntities);
            debug("doTestExternalParameterEntitiesPasses(): " + result);
            Assert.assertEquals(expected, result);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Wasn't expecting exception: " + e);
        }
    }
    
    String doTestExternalEntitiesParse(ParserType type, EntityType entityType, E systemProperty, E secureProcessing, E externalEntities) throws Exception
    {
        try
        {
            if (!E.DEFAULT.equals(systemProperty))
            {
                System.setProperty(RESOLVE_EXTERNAL_ENTITIES_PROPERTY_NAME, systemProperty.toString());
            }
            ParserFactory factory = ParserFactory.newInstance(type);
            factory.setFeature(DISALLOW_DOCTYPE_DECL_FEATURE, false);
            if (!E.DEFAULT.equals(secureProcessing))
            {
                factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, secureProcessing.bool());
            }
            if (!E.DEFAULT.equals(externalEntities))
            {
                if (EntityType.GENERAL.equals(entityType))
                {
                    factory.setFeature(EXTERNAL_GENERAL_ENTITIES_FEATURE, externalEntities.bool()); 
                }
                else
                {
                    factory.setFeature(EXTERNAL_PARAMETER_ENTITIES_FEATURE, externalEntities.bool());
                }
            }
            factory.setFeature(NAMESPACES, namespaces());
            factory.setValidating(validating());
            Parser parser = factory.newParser();
            ByteArrayInputStream baos = null;
            if (EntityType.GENERAL.equals(entityType))
            {
                baos = new ByteArrayInputStream(getExternalGeneralEntityDoc().getBytes());
            }
            else
            {
                baos = new ByteArrayInputStream(getExternalParameterEntityDoc().getBytes());
            }
            
            parser.parse(baos);
            return parser.getText();
        }
        finally
        {
            if (!E.DEFAULT.equals(systemProperty))
            {
                System.setProperty(RESOLVE_EXTERNAL_ENTITIES_PROPERTY_NAME, "");
            }
        }
    }
    
    
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    //  disallow doctype feature: http://apache.org/xml/features/disallow-doctype-decl
    //
    ////////////////////////////////////////////////////////////////////////////////////////////////////  
    
    @Test
    public void testDisallowDoctype() throws Exception
    {
        doTestDisallowDoctype(ParserType.SAX);
        doTestDisallowDoctype(ParserType.DOM);
    }
    
    public void doTestDisallowDoctype(ParserType type) throws Exception
    {
        // Test disallowDoctype: secure processing true, disallowDoctype true
        doTestDisallowDoctypeFails(type, E.TRUE, E.TRUE);

        // Test disallowDoctype: secure processing true, disallowDoctype false
        doTestDisallowDoctypePasses(type, E.TRUE, E.FALSE);

        // Test disallowDoctype: secure processing true, disallowDoctype omitted
        doTestDisallowDoctypeFails(type, E.TRUE, E.DEFAULT);

        // Test disallowDoctype: secure processing false, disallowDoctype true
        doTestDisallowDoctypeFails(type, E.FALSE, E.TRUE);

        // Test disallowDoctype: secure processing false, disallowDoctype false
        doTestDisallowDoctypePasses(type, E.FALSE, E.FALSE);

        // Test disallowDoctype: secure processing false, disallowDoctype omitted
        doTestDisallowDoctypePasses(type, E.FALSE, E.DEFAULT);

        // Test disallowDoctype: secure processing omitted, disallowDoctype true
        doTestDisallowDoctypeFails(type, E.DEFAULT, E.TRUE);

        // Test disallowDoctype: secure processing omitted, disallowDoctype false
        doTestDisallowDoctypePasses(type, E.DEFAULT, E.FALSE);

        // Test disallowDoctype: secure processing omitted, disallowDoctype omitted
        doTestDisallowDoctypeFails(type, E.DEFAULT, E.DEFAULT);
    }

    void doTestDisallowDoctypePasses(ParserType type, E secureProcessing, E disallowDoctype) throws Exception
    {
        try
        {
            doTestDisallowDoctypeParse(type, secureProcessing, disallowDoctype);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Wasn't expecting exception: " + e);
        }
    }
    
    void doTestDisallowDoctypeFails(ParserType type, E secureProcessing, E disallowDoctype) throws Exception
    {
        try
        {
            doTestDisallowDoctypeParse(type, secureProcessing, disallowDoctype);
            fail("Expecting exception");
        }
        catch (SAXParseException e)
        {
            debug(e);
            Assert.assertTrue(e.getMessage().contains("DOCTYPE is disallowed when the feature \"http://apache.org/xml/features/disallow-doctype-decl\" set to true."));
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Expecting SAXParseException, not " + e);
        }
    }
    
    void doTestDisallowDoctypeParse(ParserType type, E secureProcessing, E disallowDoctype) throws Exception
    {
        ParserFactory factory = ParserFactory.newInstance(type);
        if (!E.DEFAULT.equals(secureProcessing))
        {
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, secureProcessing.bool());
        }
        if (!E.DEFAULT.equals(disallowDoctype))
        {
            factory.setFeature(DISALLOW_DOCTYPE_DECL_FEATURE, disallowDoctype.bool());
        }
        factory.setFeature(NAMESPACES, namespaces());
        factory.setValidating(validating());
        Parser parser = factory.newParser();
        ByteArrayInputStream baos = new ByteArrayInputStream(getInternalDTDDoc().getBytes());
        parser.parse(baos);
    }


    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    //  Entity expansion limit property:
    //
    //  * jdk.xml.entityExpansionLimit
    //  * http://apache.org/xml/properties/entity-expansion-limit
    //
    //////////////////////////////////////////////////////////////////////////////////////////////////// 
    
    @Test
    public void testEntityExpansionLimit() throws Exception
    {
        doTestEntityExpansionLimit(ParserType.SAX);
        doTestEntityExpansionLimit(ParserType.DOM);
    }
    
    void doTestEntityExpansionLimit(ParserType type) throws Exception
    {
//                                              secure processing feature
//                                              |       system property limit
//                                              |       |      factory property limit
//                                              |       |      |      security manager limit
//                                              |       |      |      |      expected limit
        doTestEntityExpansionLimitFails(type,   E.TRUE, 12345, 34567, 45678, "45,678");
        doTestEntityExpansionLimitPasses(type,  E.TRUE, 12345, 34567,     0);
        doTestEntityExpansionLimitFails(type,   E.TRUE, 12345, 34567,    -1, "34,567");
        doTestEntityExpansionLimitFails(type,   E.TRUE, 12345,     0, 45678, "45,678");
        doTestEntityExpansionLimitPasses(type,  E.TRUE, 12345,     0,     0);
        doTestEntityExpansionLimitPasses(type,  E.TRUE, 12345,     0,    -1);
        doTestEntityExpansionLimitFails(type,   E.TRUE, 12345,    -1, 45678, "45,678");
        doTestEntityExpansionLimitPasses(type,  E.TRUE, 12345,    -1,     0);
        doTestEntityExpansionLimitFails(type,   E.TRUE, 12345,    -1,    -1, "12,345");

        doTestEntityExpansionLimitFails(type,   E.TRUE,     0, 34567, 45678, "45,678");
        doTestEntityExpansionLimitPasses(type,  E.TRUE,     0, 34567,     0);
        doTestEntityExpansionLimitFails(type,   E.TRUE,     0, 34567,    -1, "34,567");
        doTestEntityExpansionLimitFails(type,   E.TRUE,     0,     0, 45678, "45,678");
        doTestEntityExpansionLimitPasses(type,  E.TRUE,     0,     0,     0);
        doTestEntityExpansionLimitPasses(type,  E.TRUE,     0,     0,    -1);
        doTestEntityExpansionLimitFails(type,   E.TRUE,     0,    -1, 45678, "45,678");
        doTestEntityExpansionLimitPasses(type,  E.TRUE,     0,    -1,     0);
        doTestEntityExpansionLimitPasses(type,  E.TRUE,     0,    -1,    -1);

        doTestEntityExpansionLimitFails(type,   E.TRUE,    -1, 34567, 45678, "45,678");
        doTestEntityExpansionLimitPasses(type,  E.TRUE,    -1, 34567,     0);
        doTestEntityExpansionLimitFails(type,   E.TRUE,    -1, 34567,    -1, "34,567");
        doTestEntityExpansionLimitFails(type,   E.TRUE,    -1,     0, 45678, "45,678");
        doTestEntityExpansionLimitPasses(type,  E.TRUE,    -1,     0,     0);
        doTestEntityExpansionLimitPasses(type,  E.TRUE,    -1,     0,    -1);
        doTestEntityExpansionLimitFails(type,   E.TRUE,    -1,    -1, 45678, "45,678");
        doTestEntityExpansionLimitPasses(type,  E.TRUE,    -1,    -1,     0);
        doTestEntityExpansionLimitFails(type,   E.TRUE,    -1,    -1,    -1, "64,000");

        doTestEntityExpansionLimitPasses(type,  E.FALSE, 12345, 34567, 45678);
        doTestEntityExpansionLimitPasses(type,  E.FALSE, 12345, 34567,     0);
        doTestEntityExpansionLimitPasses(type,  E.FALSE, 12345, 34567,    -1);
        doTestEntityExpansionLimitPasses(type,  E.FALSE, 12345,     0, 45678);
        doTestEntityExpansionLimitPasses(type,  E.FALSE, 12345,     0,     0);
        doTestEntityExpansionLimitPasses(type,  E.FALSE, 12345,     0,    -1);
        doTestEntityExpansionLimitPasses(type,  E.FALSE, 12345,    -1, 45678);
        doTestEntityExpansionLimitPasses(type,  E.FALSE, 12345,    -1,     0);
        doTestEntityExpansionLimitPasses(type,  E.FALSE, 12345,    -1,    -1);

        doTestEntityExpansionLimitPasses(type,  E.FALSE,     0, 34567, 45678);
        doTestEntityExpansionLimitPasses(type,  E.FALSE,     0, 34567,     0);
        doTestEntityExpansionLimitPasses(type,  E.FALSE,     0, 34567,    -1);
        doTestEntityExpansionLimitPasses(type,  E.FALSE,     0,     0, 45678);
        doTestEntityExpansionLimitPasses(type,  E.FALSE,     0,     0,     0);
        doTestEntityExpansionLimitPasses(type,  E.FALSE,     0,     0,    -1);
        doTestEntityExpansionLimitPasses(type,  E.FALSE,     0,    -1, 45678);
        doTestEntityExpansionLimitPasses(type,  E.FALSE,     0,    -1,     0);
        doTestEntityExpansionLimitPasses(type,  E.FALSE,     0,    -1,    -1);

        doTestEntityExpansionLimitPasses(type,  E.FALSE,    -1, 34567, 45678);
        doTestEntityExpansionLimitPasses(type,  E.FALSE,    -1, 34567,     0);
        doTestEntityExpansionLimitPasses(type,  E.FALSE,    -1, 34567,    -1);
        doTestEntityExpansionLimitPasses(type,  E.FALSE,    -1,     0, 45678);
        doTestEntityExpansionLimitPasses(type,  E.FALSE,    -1,     0,     0);
        doTestEntityExpansionLimitPasses(type,  E.FALSE,    -1,     0,    -1);
        doTestEntityExpansionLimitPasses(type,  E.FALSE,    -1,    -1, 45678);
        doTestEntityExpansionLimitPasses(type,  E.FALSE,    -1,    -1,     0);
        doTestEntityExpansionLimitPasses(type,  E.FALSE,    -1,    -1,    -1);
        
        doTestEntityExpansionLimitFails(type,   E.DEFAULT, 12345, 34567, 45678, "45,678");
        doTestEntityExpansionLimitPasses(type,  E.DEFAULT, 12345, 34567,     0);
        doTestEntityExpansionLimitFails(type,   E.DEFAULT, 12345, 34567,    -1, "34,567");
        doTestEntityExpansionLimitFails(type,   E.DEFAULT, 12345,     0, 45678, "45,678");
        doTestEntityExpansionLimitPasses(type,  E.DEFAULT, 12345,     0,     0);
        doTestEntityExpansionLimitPasses(type,  E.DEFAULT, 12345,     0,    -1);
        doTestEntityExpansionLimitFails(type,   E.DEFAULT, 12345,    -1, 45678, "45,678");
        doTestEntityExpansionLimitPasses(type,  E.DEFAULT, 12345,    -1,     0);
        doTestEntityExpansionLimitFails(type,   E.DEFAULT, 12345,    -1,    -1, "12,345");

        doTestEntityExpansionLimitFails(type,   E.DEFAULT, 0, 34567, 45678, "45,678");
        doTestEntityExpansionLimitPasses(type,  E.DEFAULT, 0, 34567,     0);
        doTestEntityExpansionLimitFails(type,   E.DEFAULT, 0, 34567,    -1, "34,567");
        doTestEntityExpansionLimitFails(type,   E.DEFAULT, 0,     0, 45678, "45,678");
        doTestEntityExpansionLimitPasses(type,  E.DEFAULT, 0,     0,     0);
        doTestEntityExpansionLimitPasses(type,  E.DEFAULT, 0,     0,    -1);
        doTestEntityExpansionLimitFails(type,   E.DEFAULT, 0,    -1, 45678, "45,678");
        doTestEntityExpansionLimitPasses(type,  E.DEFAULT, 0,    -1,     0);
        doTestEntityExpansionLimitPasses(type,  E.DEFAULT, 0,    -1,    -1);

        doTestEntityExpansionLimitFails(type,  E.DEFAULT, -1, 34567, 45678, "45,678");
        doTestEntityExpansionLimitPasses(type, E.DEFAULT, -1, 34567,     0);
        doTestEntityExpansionLimitFails(type,  E.DEFAULT, -1, 34567,    -1, "34,567");
        doTestEntityExpansionLimitFails(type,  E.DEFAULT, -1,     0, 45678, "45,678");
        doTestEntityExpansionLimitPasses(type, E.DEFAULT, -1,     0,     0);
        doTestEntityExpansionLimitPasses(type, E.DEFAULT, -1,     0,    -1);
        doTestEntityExpansionLimitFails(type,  E.DEFAULT, -1,    -1, 45678, "45,678");
        doTestEntityExpansionLimitPasses(type, E.DEFAULT, -1,    -1,     0);
        doTestEntityExpansionLimitFails(type,  E.DEFAULT, -1,    -1,    -1, "64,000");
    }
    
    void doTestEntityExpansionLimitPasses(ParserType type, E secureProcessing, int systemLimit, int factoryLimit, int securityLimit) throws Exception
    {
        try
        {
            doTestEntityExpansionLimitParse(type, secureProcessing, systemLimit, factoryLimit, securityLimit);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Wasn't expecting exception: " + e);
        }
    }
    
    void doTestEntityExpansionLimitFails(ParserType type, E secureProcessing, int systemLimit, int factoryLimit, int securityLimit, String expectedLimit) throws Exception
    {
        try
        {
            doTestEntityExpansionLimitParse(type, secureProcessing, systemLimit, factoryLimit, securityLimit);
            fail("Expecting exception");
        }
        catch (SAXParseException e)
        {
            debug(e);
            debug("expectedLimit: " + expectedLimit);
//            e.printStackTrace();
            Assert.assertTrue(e.getMessage().contains("The parser has encountered more than \"" + expectedLimit + "\" entity expansions"));
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Expecting SAXParseException");
        }
    }
    
    void doTestEntityExpansionLimitParse(ParserType type, E secureProcessing, int systemLimit, int factoryLimit, int securityLimit) throws Exception
    {
        try
        {
            if (systemLimit > -1)
            {
                System.setProperty(ENTITY_EXPANSION_LIMIT_PROPERTY_NAME, Integer.toString(systemLimit));
            }
            ParserFactory factory = ParserFactory.newInstance(type);
            if (!E.DEFAULT.equals(secureProcessing))
            {
                factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, secureProcessing.bool());
            }
            factory.setFeature(DISALLOW_DOCTYPE_DECL_FEATURE, false);
            if (factoryLimit >=0)
            {
                factory.setProperty(getEntityExpansionLimitProperty(), factoryLimit);
            }
            factory.setFeature(NAMESPACES, namespaces());
            factory.setValidating(validating());
            Parser parser = factory.newParser();
            SecurityManager sm = (SecurityManager) parser.getProperty(SECURITY_MANAGER_PROPERTY);
            if (sm != null && securityLimit >= 0)
            {
                sm.setEntityExpansionLimit(securityLimit);
            }
            ByteArrayInputStream baos = new ByteArrayInputStream(getBigElementDoctype().getBytes(Charset.forName("UTF-8")));
            parser.parse(baos);
        }
        finally
        {
            System.setProperty(ENTITY_EXPANSION_LIMIT_PROPERTY_NAME, "");
        }
    }
    

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    //  element attribute limit:
    //
    //  * jdk.xml.elementAttributeLimit
    //  * http://apache.org/xml/properties/elementAttributeLimit
    //
    ////////////////////////////////////////////////////////////////////////////////////////////////////  
    
    @Test
    public void testElementAttributeLimit() throws Exception
    {
        doTestElementAttributeLimit(ParserType.SAX);
        doTestElementAttributeLimit(ParserType.DOM);
    }
    
    void doTestElementAttributeLimit(ParserType type) throws Exception
    {
//                                              secure processing feature
//                                              |       system property limit
//                                              |       |       factory property limit
//                                              |       |       |     security manager limit
//                                              |       |       |     |     expected limit
        doTestElementAttributeLimitFails(type,  E.TRUE, "23", 34, 45, "45");
        doTestElementAttributeLimitPasses(type, E.TRUE, "23", 34,  0);
        doTestElementAttributeLimitFails(type,  E.TRUE, "23", 34, -1, "34");
        doTestElementAttributeLimitFails(type,  E.TRUE, "23",  0, 45, "45");
        doTestElementAttributeLimitPasses(type, E.TRUE, "23",  0,  0);
        doTestElementAttributeLimitPasses(type, E.TRUE, "23",  0, -1);
        doTestElementAttributeLimitFails(type,  E.TRUE, "23", -1, 45, "45");
        doTestElementAttributeLimitPasses(type, E.TRUE, "23", -1,  0);
        doTestElementAttributeLimitFails(type,  E.TRUE, "23", -1, -1, "23");

        doTestElementAttributeLimitFails(type,  E.TRUE, "0", 34, 45, "45");
        doTestElementAttributeLimitPasses(type, E.TRUE, "0", 34,  0);
        doTestElementAttributeLimitFails(type,  E.TRUE, "0", 34, -1, "34");
        doTestElementAttributeLimitFails(type,  E.TRUE, "0",  0, 45, "45");
        doTestElementAttributeLimitPasses(type, E.TRUE, "0",  0,  0);
        doTestElementAttributeLimitPasses(type, E.TRUE, "0",  0, -1);
        doTestElementAttributeLimitFails(type,  E.TRUE, "0", -1, 45, "45");
        doTestElementAttributeLimitPasses(type, E.TRUE, "0", -1,  0);
        doTestElementAttributeLimitPasses(type, E.TRUE, "0", -1, -1);

        doTestElementAttributeLimitFails(type,  E.TRUE, "-1", 34, 45, "45");
        doTestElementAttributeLimitPasses(type, E.TRUE, "-1", 34,  0);
        doTestElementAttributeLimitFails(type,  E.TRUE, "-1", 34, -1, "34");
        doTestElementAttributeLimitFails(type,  E.TRUE, "-1",  0, 45, "45");
        doTestElementAttributeLimitPasses(type, E.TRUE, "-1",  0,  0);
        doTestElementAttributeLimitPasses(type, E.TRUE, "-1",  0, -1);
        doTestElementAttributeLimitFails(type,  E.TRUE, "-1", -1, 45, "45");
        doTestElementAttributeLimitPasses(type, E.TRUE, "-1", -1,  0);
        doTestElementAttributeLimitFails(type,  E.TRUE, "-1", -1, -1, "10000");

        doTestElementAttributeLimitPasses(type, E.FALSE, "23", 34, 45);
        doTestElementAttributeLimitPasses(type, E.FALSE, "23", 34,  0);
        doTestElementAttributeLimitPasses(type, E.FALSE, "23", 34, -1);
        doTestElementAttributeLimitPasses(type, E.FALSE, "23",  0, 45);
        doTestElementAttributeLimitPasses(type, E.FALSE, "23",  0,  0);
        doTestElementAttributeLimitPasses(type, E.FALSE, "23",  0, -1);        
        doTestElementAttributeLimitPasses(type, E.FALSE, "23", -1, 45);
        doTestElementAttributeLimitPasses(type, E.FALSE, "23", -1,  0);
        doTestElementAttributeLimitPasses(type, E.FALSE, "23", -1, -1);

        doTestElementAttributeLimitPasses(type, E.FALSE, "0", 34, 45);
        doTestElementAttributeLimitPasses(type, E.FALSE, "0", 34,  0);
        doTestElementAttributeLimitPasses(type, E.FALSE, "0", 34, -1);
        doTestElementAttributeLimitPasses(type, E.FALSE, "0",  0, 45);
        doTestElementAttributeLimitPasses(type, E.FALSE, "0",  0,  0);
        doTestElementAttributeLimitPasses(type, E.FALSE, "0",  0, -1);        
        doTestElementAttributeLimitPasses(type, E.FALSE, "0", -1, 45);
        doTestElementAttributeLimitPasses(type, E.FALSE, "0", -1,  0);
        doTestElementAttributeLimitPasses(type, E.FALSE, "0", -1, -1);

        doTestElementAttributeLimitPasses(type, E.FALSE, "-1", 34, 45);
        doTestElementAttributeLimitPasses(type, E.FALSE, "-1", 34,  0);
        doTestElementAttributeLimitPasses(type, E.FALSE, "-1", 34, -1);
        doTestElementAttributeLimitPasses(type, E.FALSE, "-1",  0, 45);
        doTestElementAttributeLimitPasses(type, E.FALSE, "-1",  0,  0);
        doTestElementAttributeLimitPasses(type, E.FALSE, "-1",  0, -1);        
        doTestElementAttributeLimitPasses(type, E.FALSE, "-1", -1, 45);
        doTestElementAttributeLimitPasses(type, E.FALSE, "-1", -1,  0);
        doTestElementAttributeLimitPasses(type, E.FALSE, "-1", -1, -1);

        doTestElementAttributeLimitFails(type,  E.DEFAULT, "23", 34, 45, "45");
        doTestElementAttributeLimitPasses(type, E.DEFAULT, "23", 34,  0);
        doTestElementAttributeLimitFails(type,  E.DEFAULT, "23", 34, -1, "34");
        doTestElementAttributeLimitFails(type,  E.DEFAULT, "23",  0, 45, "45");
        doTestElementAttributeLimitPasses(type, E.DEFAULT, "23",  0,  0);
        doTestElementAttributeLimitPasses(type, E.DEFAULT, "23",  0, -1);
        doTestElementAttributeLimitFails(type,  E.DEFAULT, "23", -1, 45, "45");
        doTestElementAttributeLimitPasses(type, E.DEFAULT, "23", -1,  0);
        doTestElementAttributeLimitFails(type,  E.DEFAULT, "23", -1, -1, "23");

        doTestElementAttributeLimitFails(type,  E.DEFAULT, "0", 34, 45, "45");
        doTestElementAttributeLimitPasses(type, E.DEFAULT, "0", 34,  0);
        doTestElementAttributeLimitFails(type,  E.DEFAULT, "0", 34, -1, "34");
        doTestElementAttributeLimitFails(type,  E.DEFAULT, "0",  0, 45, "45");
        doTestElementAttributeLimitPasses(type, E.DEFAULT, "0",  0,  0);
        doTestElementAttributeLimitPasses(type, E.DEFAULT, "0",  0, -1);
        doTestElementAttributeLimitFails(type,  E.DEFAULT, "0", -1, 45, "45");
        doTestElementAttributeLimitPasses(type, E.DEFAULT, "0", -1,  0);
        doTestElementAttributeLimitPasses(type, E.DEFAULT, "0", -1, -1);

        doTestElementAttributeLimitFails(type,  E.DEFAULT, "-1", 34, 45, "45");
        doTestElementAttributeLimitPasses(type, E.DEFAULT, "-1", 34,  0);
        doTestElementAttributeLimitFails(type,  E.DEFAULT, "-1", 34, -1, "34");
        doTestElementAttributeLimitFails(type,  E.DEFAULT, "-1",  0, 45, "45");
        doTestElementAttributeLimitPasses(type, E.DEFAULT, "-1",  0,  0);
        doTestElementAttributeLimitPasses(type, E.DEFAULT, "-1",  0, -1);
        doTestElementAttributeLimitFails(type,  E.DEFAULT, "-1", -1, 45, "45");
        doTestElementAttributeLimitPasses(type, E.DEFAULT, "-1", -1,  0);
        doTestElementAttributeLimitFails(type,  E.DEFAULT, "-1", -1, -1, "10000");
    }
    
    void doTestElementAttributeLimitPasses(ParserType type, E secureProcessing, String systemLimit, int factoryLimit, int securityLimit)
    {
        try
        {
            doTestElementAttributeLimitParse(type, secureProcessing, systemLimit, factoryLimit, securityLimit); 
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Wasn't expecting exception: " + e);
        }
    }
    
    void doTestElementAttributeLimitFails(ParserType type, E secureProcessing, String systemLimit, int factoryLimit, int securityLimit, String expected)
    {
        try
        {
            doTestElementAttributeLimitParse(type, secureProcessing, systemLimit, factoryLimit, securityLimit);
            fail("Expecting SAXParseException");
        }
        catch (SAXParseException e)
        {
            debug(e);
            Assert.assertTrue(e.getMessage().contains("has more than \"" + expected + "\" attributes"));
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Expecting SAXParseException");
        }
    }    
    
    void doTestElementAttributeLimitParse(ParserType type, E secureProcessing, String systemLimit, int factoryLimit, int securityLimit) throws Exception
    {
        try
        {
            if (Integer.valueOf(systemLimit).intValue() > -1)
            {
                System.setProperty(ELEMENT_ATTRIBUTE_LIMIT_PROPERTY_NAME, systemLimit);
            }
            ParserFactory factory = ParserFactory.newInstance(type);
            if (!E.DEFAULT.equals(secureProcessing))
            {
                factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, secureProcessing.bool());
            }
            factory.setFeature(DISALLOW_DOCTYPE_DECL_FEATURE, false);
            factory.setFeature(NAMESPACES, true);
            factory.setValidating(validating());
            if (factoryLimit >=0)
            {
                factory.setProperty(getElementAttributeLimitProperty(), factoryLimit);
            }
            Parser parser = factory.newParser();
            if (securityLimit >= 0)
            {
                SecurityManager sm = (SecurityManager) parser.getProperty(SECURITY_MANAGER_PROPERTY);
                if (sm != null)
                {
                    sm.setElementAttributeLimit(securityLimit);
                }
            }
            String doc = null;
            if ("-1".equals(systemLimit) && factoryLimit == -1 && securityLimit == -1)
            {
                doc = getReallyBigAttributeDoc();
            }
            else
            {
                doc = getBigAttributeDoc();
            }
            ByteArrayInputStream baos = new ByteArrayInputStream(doc.getBytes(Charset.forName("UTF-8")));
            parser.parse(baos);
        }
        finally
        {
            if (Integer.valueOf(systemLimit).intValue() > -1)
            {
                System.setProperty(ELEMENT_ATTRIBUTE_LIMIT_PROPERTY_NAME, "");
            }
        }
    }
    
    
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    //  max occurs limit:
    //
    //  * jdk.xml.maxOccur
    //  * http://www.oracle.com/xml/jaxp/properties/maxOccurLimit
    //
    ////////////////////////////////////////////////////////////////////////////////////////////////////  
    
    @Test
    public void testMaxOccursSchema() throws Exception
    {
        String s = "<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\">" +
                      "<xs:element name=\"foo\">" +
                         "<xs:complexType >" +
                            "<xs:sequence minOccurs=\"0\" maxOccurs=\"10000\">" +
                               "<xs:element name=\"bar\" type=\"xs:string\"/>" +
                            "</xs:sequence>" +
                         "</xs:complexType>" +
                      "</xs:element>" +
                   "</xs:schema>";
        try
        {
            ByteArrayInputStream bais = new ByteArrayInputStream(s.getBytes());
            SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = sf.newSchema(new StreamSource(bais));
            debug("schema: " + schema);
            Assert.assertNotNull(schema);
        }
        catch (SAXParseException e)
        {
            e.printStackTrace();
            debug(e);
            Assert.assertTrue(e.getMessage().contains("Current configuration of the parser doesn't allow the expansion of a content model for a complex type to contain more than 5,000 nodes."));
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Expected SAXParseException, not " + e.getLocalizedMessage());
        } 
    }

    @Test
    public void testMaxOccurs() throws Exception
    {
        doTestMaxOccurs(ParserType.SAX);
        doTestMaxOccurs(ParserType.DOM);
    }
    
    void doTestMaxOccurs(ParserType type) throws Exception
    {
        // Notes.
        //
        // 1. The maxOccurs property is tested only when the secure processing feature is turned on.
        // 2. The value set in the SecurityManager overrides the system property.
        // 3. Any value <= 0 is treated as Integer.MAX_VALUE.
        // 4. The test sets the system property or the SecurityManager value only when the value is >= 0.
        //    I.e., it is not set for -1.
        
//                                  secure processing feature
//                                  |       system property limit
//                                  |       |     factory property limit
//                                  |       |     |     security manager limit
//                                  |       |     |     |      expected limit
        doTestMaxOccursFails(type,  E.TRUE, 3456, 4567, 5678, "5,678");
        doTestMaxOccursPasses(type, E.TRUE, 3456, 4567,    0);
        doTestMaxOccursFails(type,  E.TRUE, 3456, 4567,   -1, "4,567");
        doTestMaxOccursFails(type,  E.TRUE, 3456,    0, 5678, "5,678");
        doTestMaxOccursPasses(type, E.TRUE, 3456,    0,    0);        
        doTestMaxOccursPasses(type, E.TRUE, 3456,    0,   -1);
        doTestMaxOccursFails(type,  E.TRUE, 3456,   -1, 5678, "5,678");
        doTestMaxOccursPasses(type, E.TRUE, 3456,   -1,    0);        
        doTestMaxOccursFails(type,  E.TRUE, 3456,   -1,   -1, "3,456");
        
        doTestMaxOccursFails(type,  E.TRUE,    0, 4567, 5678, "5,678");
        doTestMaxOccursPasses(type, E.TRUE,    0, 4567,    0);
        doTestMaxOccursFails(type,  E.TRUE,    0, 4567,   -1, "4,567");
        doTestMaxOccursFails(type,  E.TRUE,    0,    0, 5678, "5,678");
        doTestMaxOccursPasses(type, E.TRUE,    0,    0,    0);        
        doTestMaxOccursPasses(type, E.TRUE,    0,    0,   -1);
        doTestMaxOccursFails(type,  E.TRUE,    0,   -1, 5678, "5,678");
        doTestMaxOccursPasses(type, E.TRUE,    0,   -1,    0);        
        doTestMaxOccursPasses(type, E.TRUE,    0,   -1,   -1);
        
        doTestMaxOccursFails(type,  E.TRUE,   -1, 4567, 5678, "5,678");
        doTestMaxOccursPasses(type, E.TRUE,   -1, 4567,    0);
        doTestMaxOccursFails(type,  E.TRUE,   -1, 4567,   -1, "4,567");
        doTestMaxOccursFails(type,  E.TRUE,   -1,    0, 5678, "5,678");
        doTestMaxOccursPasses(type, E.TRUE,   -1,    0,    0);        
        doTestMaxOccursPasses(type, E.TRUE,   -1,    0,   -1);
        doTestMaxOccursFails(type,  E.TRUE,   -1,   -1, 5678, "5,678");
        doTestMaxOccursPasses(type, E.TRUE,   -1,   -1,    0);        
        doTestMaxOccursFails(type,  E.TRUE,   -1,   -1,   -1, "5,000"); // default is 5000
        
        doTestMaxOccursPasses(type,  E.FALSE, 3456, 4567, 5678);
        doTestMaxOccursPasses(type,  E.FALSE, 3456, 4567,    0);
        doTestMaxOccursPasses(type,  E.FALSE, 3456, 4567,   -1);
        doTestMaxOccursPasses(type,  E.FALSE, 3456,    0, 5678);
        doTestMaxOccursPasses(type,  E.FALSE, 3456,    0,    0);        
        doTestMaxOccursPasses(type,  E.FALSE, 3456,    0,   -1);
        doTestMaxOccursPasses(type,  E.FALSE, 3456,   -1, 5678);
        doTestMaxOccursPasses(type,  E.FALSE, 3456,   -1,    0);        
        doTestMaxOccursPasses(type,  E.FALSE, 3456,   -1,   -1);
        
        doTestMaxOccursPasses(type,  E.FALSE,    0, 4567, 5678);
        doTestMaxOccursPasses(type,  E.FALSE,    0, 4567,    0);
        doTestMaxOccursPasses(type,  E.FALSE,    0, 4567,   -1);
        doTestMaxOccursPasses(type,  E.FALSE,    0,    0, 5678);
        doTestMaxOccursPasses(type,  E.FALSE,    0,    0,    0);        
        doTestMaxOccursPasses(type,  E.FALSE,    0,    0,   -1);
        doTestMaxOccursPasses(type,  E.FALSE,    0,   -1, 5678);
        doTestMaxOccursPasses(type,  E.FALSE,    0,   -1,    0);        
        doTestMaxOccursPasses(type,  E.FALSE,    0,   -1,   -1);
        
        doTestMaxOccursPasses(type,  E.FALSE,   -1, 4567, 5678);
        doTestMaxOccursPasses(type,  E.FALSE,   -1, 4567,    0);
        doTestMaxOccursPasses(type,  E.FALSE,   -1, 4567,   -1);
        doTestMaxOccursPasses(type,  E.FALSE,   -1,    0, 5678);
        doTestMaxOccursPasses(type,  E.FALSE,   -1,    0,    0);        
        doTestMaxOccursPasses(type,  E.FALSE,   -1,    0,   -1);
        doTestMaxOccursPasses(type,  E.FALSE,   -1,   -1, 5678);
        doTestMaxOccursPasses(type,  E.FALSE,   -1,   -1,    0);        
        doTestMaxOccursPasses(type,  E.FALSE,   -1,   -1,   -1);
        
        doTestMaxOccursFails(type,  E.DEFAULT, 3456, 4567, 5678, "5,678");
        doTestMaxOccursPasses(type, E.DEFAULT, 3456, 4567,    0);
        doTestMaxOccursFails(type,  E.DEFAULT, 3456, 4567,   -1, "4,567");
        doTestMaxOccursFails(type,  E.DEFAULT, 3456,    0, 5678, "5,678");
        doTestMaxOccursPasses(type, E.DEFAULT, 3456,    0,    0);        
        doTestMaxOccursPasses(type, E.DEFAULT, 3456,    0,   -1);
        doTestMaxOccursFails(type,  E.DEFAULT, 3456,   -1, 5678, "5,678");
        doTestMaxOccursPasses(type, E.DEFAULT, 3456,   -1,    0);        
        doTestMaxOccursFails(type,  E.DEFAULT, 3456,   -1,   -1, "3,456");
        
        doTestMaxOccursFails(type,  E.DEFAULT,    0, 4567, 5678, "5,678");
        doTestMaxOccursPasses(type, E.DEFAULT,    0, 4567,    0);
        doTestMaxOccursFails(type,  E.DEFAULT,    0, 4567,   -1, "4,567");
        doTestMaxOccursFails(type,  E.DEFAULT,    0,    0, 5678, "5,678");
        doTestMaxOccursPasses(type, E.DEFAULT,    0,    0,    0);        
        doTestMaxOccursPasses(type, E.DEFAULT,    0,    0,   -1);
        doTestMaxOccursFails(type,  E.DEFAULT,    0,   -1, 5678, "5,678");
        doTestMaxOccursPasses(type, E.DEFAULT,    0,   -1,    0);        
        doTestMaxOccursPasses(type, E.DEFAULT,    0,   -1,   -1);
        
        doTestMaxOccursFails(type,  E.DEFAULT,   -1, 4567, 5678, "5,678");
        doTestMaxOccursPasses(type, E.DEFAULT,   -1, 4567,    0);
        doTestMaxOccursFails(type,  E.DEFAULT,   -1, 4567,   -1, "4,567");
        doTestMaxOccursFails(type,  E.DEFAULT,   -1,    0, 5678, "5,678");
        doTestMaxOccursPasses(type, E.DEFAULT,   -1,    0,    0);        
        doTestMaxOccursPasses(type, E.DEFAULT,   -1,    0,   -1);
        doTestMaxOccursFails(type,  E.DEFAULT,   -1,   -1, 5678, "5,678");
        doTestMaxOccursPasses(type, E.DEFAULT,   -1,   -1,    0);        
        doTestMaxOccursFails(type,  E.DEFAULT,   -1,   -1,   -1, "5,000"); // default is 5000
    }
    
    void doTestMaxOccursPasses(ParserType type, E secureProcessing, int systemLimit, int factoryLimit, int securityLimit) throws Exception
    {
        try
        {
            doTestMaxOccursParse(type, secureProcessing, systemLimit, factoryLimit, securityLimit);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Wasn't expecting exception: " + e);
        }
    }
    
    void doTestMaxOccursFails(ParserType type, E secureProcessing, int systemLimit, int factoryLimit, int securityLimit, String expected) throws Exception
    {
        try
        {
            doTestMaxOccursParse(type, secureProcessing, systemLimit, factoryLimit, securityLimit);
            fail("Expecting exception");
        }
        catch (SAXParseException e)
        {
            debug(e);
            Assert.assertTrue(e.getLocalizedMessage().contains("Current configuration of the parser doesn't allow the expansion of a content model for a complex type to contain more than " + expected + " nodes."));
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Expecting SAXParseException, not " + e);
        }
    }
    
    void doTestMaxOccursParse(ParserType type, E secureProcessing, int systemLimit, int factoryLimit, int securityLimit) throws Exception
    {
        try
        {
            System.setProperty(RESOLVE_EXTERNAL_ENTITIES_PROPERTY_NAME, "true");
            System.setProperty(ACCESS_EXTERNAL_SCHEMA_PROPERTY_NAME, "all");
            if (systemLimit >= 0)
            {
                System.setProperty(MAX_OCCUR_LIMIT_PROPERTY_NAME, Integer.toString(systemLimit));
            }
            ParserFactory factory = ParserFactory.newInstance(type);
            factory.setValidating(true); // maxOccur is checked by validating parser
            factory.setNamespaceAware(true);
            factory.setProperty(JAXPConstants.JAXP_SCHEMA_LANGUAGE, XMLConstants.W3C_XML_SCHEMA_NS_URI);
            if (!E.DEFAULT.equals(secureProcessing))
            {
                factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, secureProcessing.bool());
            }
            factory.setFeature(NAMESPACES, true);
            Parser parser = factory.newParser();
            if (factoryLimit >= 0)
            {
                parser.setProperty(MAX_OCCUR_LIMIT, factoryLimit);
            }
            if (securityLimit >= 0)
            {
                SecurityManager sm = (SecurityManager) parser.getProperty(SECURITY_MANAGER_PROPERTY);
                if (sm != null)
                {
                    sm.setMaxOccurNodeLimit(securityLimit);
                }
            }
            TestErrorHandler errorHandler = new TestErrorHandler();
            parser.setErrorHandler(errorHandler);
            ByteArrayInputStream baos = new ByteArrayInputStream(getMaxOccursDoc().getBytes(Charset.forName("UTF-8")));
            parser.parse(baos);
        }
        finally
        {
            if (systemLimit >= 0)
            {
                System.setProperty(MAX_OCCUR_LIMIT_PROPERTY_NAME, "");
            }
        }
    }
    
    
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    //  Load external DTD feature, Access external DTD property:
    //
    //  * jdk.xml.resolveExternalEntities
    //  * javax.xml.accessExternalDTD
    //  * http://apache.org/xml/features/nonvalidating/load-external-dtd
    //
    ////////////////////////////////////////////////////////////////////////////////////////////////////  
    
    @Test
    public void testExternalDTD() throws Exception
    {
        doTestExternalDTD(ParserType.SAX);
        doTestExternalDTD(ParserType.DOM);
    }
    
    void doTestExternalDTD(ParserType type) throws Exception
    {
        // Notes.
        //
        // 1. There are several features and properties that determine if an external DTD will be loaded.
        //
        //    a. SECURE_PROCESSING_FEATURE: When true, it imposes a number of property and feature restrictions. For example,
        //       by default it will set the LOAD_EXTERNAL_DTD feature to false. The default value of SECURE_PROCESSING_FEATURE
        //       is true.
        //
        //    b. RESOLVE_EXTERNAL_ENTITIES_PROPERTY property: It is relevant only when SECURE_PROCESSING_FEATURE is true.
        //       When set to false, it will, among other things, set the LOAD_EXTERNAL_DTD feature to false. When the 
        //       SECURE_PROCESSING_FEATURE feature is true and the RESOLVE_EXTERNAL_ENTITIES_PROPERTY_NAME property is true,
        //       the LOAD_EXTERNAL_DTD feature defaults to true. The default value of RESOLVE_EXTERNAL_ENTITIES_PROPERTY
        //       is false.
        //    
        //    c. LOAD_EXTERNAL_DTD feature: when set to false, external DTDs will not be loaded. When SECURE_PROCESSING_FEATURE
        //       is true, the value of LOAD_EXTERNAL_DTD is determined as above. If SECURE_PROCESSING_FEATURE is false,
        //       LOAD_EXTERNAL_DTD defaults to true.
        //
        //    d. VALIDATION: LOAD_EXTERNAL_DTD (http://apache.org/xml/features/nonvalidating/load-external-dtd) is relevant only when validation
        //       is turned off. When validation is turned on, external DTDs are loaded if permitted by the other features and properties.
        //
        //    e. DISALLOW_DOCTYPE feature: When set to true, no DTDs, internal or external, are permitted. When SECURE_PROCESSING_FEATURE
        //       is true, it defaults to true. Otherwise, it defaults to false.
        //
        //    f. ACCESS_EXTERNAL_DTD property: When configuration allows the loading of external DTDs, this property can be set to a comma
        //       separated list of protocols, e.g., "jar,file", by which DTDs may be loaded. 
        //       
        //       i. If SECURE_PROCESSING_FEATURE is false, ACCESS_EXTERNAL_DTD defaults to "all", meaning all protocols may be used.
        //      ii. If SECURE_PROCESSING_FEATURE is true and RESOLVE_EXTERNAL_ENTITIES_PROPERTY is false (the default value),
        //          ACCESS_EXTERNAL_DTD defaults to "", meaning no protocols may be used.
        //     iii. If SECURE_PROCESSING_FEATURE is true and RESOLVE_EXTERNAL_ENTITIES_PROPERTY is true, ACCESS_EXTERNAL_DTD defaults to "all"
        //
        //       As with many security related properties, ACCESS_EXTERNAL_DTD may, if SECURE_PROCESSING_FEATURE is true,
        //       be set in several ways:
        //
        //       i. "javax.xml.accessExternalDTD" system property
        //      ii. "http://javax.xml.XMLConstants/property/accessExternalDTD" parser / parser factory property
        //     iii. SecurityManager.setAccessExternalDTD()
        //
        // 2. In this test, since we're testing external DTDs, DISALLOW_DOCTYPE is always set to false.
        //
        // 3. Depending on the combination of features and properties, one of two things can happen:
        //
        //    a. If loading of external DTDs is permitted, the the general entity &foo; will be retrieved from an external DTD
        //       and doTestExternalDTDParse() will return the string "foo";.
        //
        //    b. If loading of external DTDs is not permitted, parsing will succeed and doTestExternalDTDParse() will return "".
        //
        
//////////////////////////////////////////
//      TRUE, TRUE, TRUE
//                              RESOLVE_EXTERNAL_ENTITIES_PROPERTY
//                              |       SECURE_PROCESSING_FEATURE
//                              |       |       LOAD_EXTERNAL_DTD
//                              |       |       |       system property value
//                              |       |       |       |      factory property limit
//                              |       |       |       |      |      security manager limit
//                              |       |       |       |      |      |      expected limit
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "all", "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "all", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "all", "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "all", "all", null, "foo");
        
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "all", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "all", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "all", "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "all", "jar,file", null, "foo");
        
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "all", "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "all", "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "all", "", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "all", "", null, "");
        
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "all", null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "all", null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "all", null, "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "all", null, null, "foo");
        
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "jar,file", "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "jar,file", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "jar,file", "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "jar,file", "all", null, "foo");
        
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "jar,file", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "jar,file", "jar,file", "jar,file", "foo");        
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "jar,file", "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "jar,file", "jar,file", null, "foo");
        
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "jar,file", "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "jar,file", "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "jar,file", "", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "jar,file", "", null, "");
        
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "jar,file", null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "jar,file", null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "jar,file", null, "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "jar,file", null, null, "foo");
        
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "", "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "", "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "", "all", null, "foo");
        
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "", "jar,file", "jar,file", "foo"); 
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "", "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "", "jar,file", null, "foo");
        
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "", "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "", "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "", "", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "", "", null, "");
        
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "", null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "", null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "", null, "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, "", null, null, "");
        
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, null, "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, null, "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, null, "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, null, "all", null, "foo");
        
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, null, "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, null, "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, null, "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, null, "jar,file", null, "foo");
        
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, null, "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, null, "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, null, "", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, null, "", null, "");
        
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, null, null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, null, null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, null, null, "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.TRUE, null, null, null, "foo");
//        
////////////////////////////////////////////
//      TRUE, TRUE, FALSE
//        
//      LOAD_EXTERNAL_DTD = false overrides
     
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "all", "all", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "all", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "all", "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "all", "all", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "all", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "all", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "all", "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "all", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "all", "", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "all", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "all", "", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "all", "", null, "");

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "all", null, "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "all", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "all", null, "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "all", null, null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "jar,file", "all", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "jar,file", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "jar,file", "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "jar,file", "all", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "jar,file", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "jar,file", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "jar,file", "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "jar,file", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "jar,file", "", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "jar,file", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "jar,file", "", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "jar,file", "", null, "");

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "jar,file", null, "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "jar,file", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "jar,file", null, "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "jar,file", null, null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "", "all", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "", "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "", "all", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "", "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "", "", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "", "", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "", "", null, "");

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "", null, "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "", null, "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, "", null, null, "");

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, null, "all", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, null, "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, null, "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, null, "all", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, null, "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, null, "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, null, "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, null, "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, null, "", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, null, "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, null, "", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, null, "", null, "");

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, null, null, "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, null, null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, null, null, "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.FALSE, null, null, null, ifValidating());
//      
////////////////////////////////////////////
//      TRUE, TRUE, DEFAULT
        
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "all", "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "all", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "all", "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "all", "all", null, "foo");
  
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "all", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "all", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "all", "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "all", "jar,file", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "all", "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "all", "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "all", "", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "all", "", null, "");

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "all", null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "all", null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "all", null, "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "all", null, null, "foo");
        
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "jar,file", "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "jar,file", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "jar,file", "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "jar,file", "all", null, "foo");
  
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "jar,file", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "jar,file", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "jar,file", "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "jar,file", "jar,file", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "jar,file", "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "jar,file", "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "jar,file", "", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "jar,file", "", null, "");

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "jar,file", null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "jar,file", null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "jar,file", null, "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "jar,file", null, null, "foo");
        
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "", "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "", "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "", "all", null, "foo");
  
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "", "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "", "jar,file", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "", "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "", "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "", "", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "", "", null, "");

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "", null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "", null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "", null, "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, "", null, null, "");
        
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, null, "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, null, "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, null, "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, null, "all", null, "foo");
  
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, null, "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, null, "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, null, "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, null, "jar,file", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, null, "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, null, "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, null, "", "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, null, "", null, "");

        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, null, null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, null, null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, null, null, "", "");
        doTestExternalDTD(type, E.TRUE, E.TRUE, E.DEFAULT, null, null, null, "foo");
////
//////////////////////////////////////////////
////      TRUE, FALSE, TRUE
////    
////      SECURE_PROCESSING_FEATURE = false, so "javax.xml.accessExternalDTD" is ignored and
////      there is no SecurityManager.
//        
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "all", "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "all", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "all", "all", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "all", "all", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "all", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "all", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "all", "jar,file", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "all", "jar,file", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "all", "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "all", "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "all", "", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "all", "", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "all", null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "all", null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "all", null, "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "all", null, null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "jar,file", "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "jar,file", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "jar,file", "all", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "jar,file", "all", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "jar,file", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "jar,file", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "jar,file", "jar,file", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "jar,file", "jar,file", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "jar,file", "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "jar,file", "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "jar,file", "", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "jar,file", "", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "jar,file", null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "jar,file", null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "jar,file", null, "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "jar,file", null, null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "", "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "", "all", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "", "all", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "", "jar,file", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "", "jar,file", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "", "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "", "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "", "", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "", "", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "", null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "", null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "", null, "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, "", null, null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, null, "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, null, "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, null, "all", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, null, "all", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, null, "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, null, "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, null, "jar,file", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, null, "jar,file", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, null, "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, null, "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, null, "", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, null, "", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, null, null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, null, null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, null, null, "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.TRUE, null, null, null, "foo");
////
//////////////////////////////////////////////
////      TRUE, FALSE, FALSE
////  
////      LOAD_EXTERNAL_DTD = false overrides.
//        
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "all", "all", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "all", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "all", "all", "", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "all", "all", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "all", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "all", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "all", "jar,file", "", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "all", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "all", "", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "all", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "all", "", "", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "all", "", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "all", null, "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "all", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "all", null, "", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "all", null, null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "jar,file", "all", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "jar,file", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "jar,file", "all", "", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "jar,file", "all", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "jar,file", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "jar,file", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "jar,file", "jar,file", "", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "jar,file", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "jar,file", "", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "jar,file", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "jar,file", "", "", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "jar,file", "", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "jar,file", null, "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "jar,file", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "jar,file", null, "", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "jar,file", null, null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "", "all", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "", "all", "", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "", "all", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "", "jar,file", "", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "", "", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "", "", "", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "", "", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "", null, "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "", null, "", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, "", null, null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, null, "all", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, null, "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, null, "all", "", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, null, "all", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, null, "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, null, "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, null, "jar,file", "", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, null, "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, null, "", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, null, "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, null, "", "", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, null, "", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, null, null, "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, null, null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, null, null, "", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.FALSE, null, null, null, ifValidating());
////
//////////////////////////////////////////////
////      TRUE, FALSE, DEFAULT
////    
////      SECURE_PROCESSING_FEATURE = false, so only factory/parser property is examined.
////      LOAD_EXTERNAL_DTD defaults to true when SECURE_PROCESSING_FEATURE is false  
//        
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "all", "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "all", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "all", "all", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "all", "all", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "all", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "all", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "all", "jar,file", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "all", "jar,file", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "all", "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "all", "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "all", "", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "all", "", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "all", null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "all", null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "all", null, "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "all", null, null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "jar,file", "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "jar,file", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "jar,file", "all", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "jar,file", "all", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "jar,file", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "jar,file", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "jar,file", "jar,file", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "jar,file", "jar,file", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "jar,file", "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "jar,file", "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "jar,file", "", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "jar,file", "", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "jar,file", null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "jar,file", null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "jar,file", null, "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "jar,file", null, null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "", "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "", "all", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "", "all", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "", "jar,file", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "", "jar,file", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "", "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "", "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "", "", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "", "", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "", null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "", null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "", null, "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, "", null, null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, null, "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, null, "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, null, "all", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, null, "all", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, null, "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, null, "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, null, "jar,file", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, null, "jar,file", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, null, "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, null, "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, null, "", "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, null, "", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, null, null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, null, null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, null, null, "", "foo");
        doTestExternalDTD(type, E.TRUE, E.FALSE, E.DEFAULT, null, null, null, "foo");
////
//////////////////////////////////////////////
////      TRUE, DEFAULT, TRUE
//    
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "all", "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "all", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "all", "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "all", "all", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "all", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "all", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "all", "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "all", "jar,file", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "all", "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "all", "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "all", "", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "all", "", null, "");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "all", null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "all", null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "all", null, "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "all", null, null, "foo");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "jar,file", "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "jar,file", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "jar,file", "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "jar,file", "all", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "jar,file", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "jar,file", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "jar,file", "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "jar,file", "jar,file", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "jar,file", "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "jar,file", "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "jar,file", "", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "jar,file", "", null, "");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "jar,file", null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "jar,file", null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "jar,file", null, "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "jar,file", null, null, "foo");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "", "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "", "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "", "all", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "", "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "", "jar,file", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "", "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "", "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "", "", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "", "", null, "");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "", null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "", null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "", null, "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, "", null, null, "");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, null, "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, null, "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, null, "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, null, "all", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, null, "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, null, "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, null, "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, null, "jar,file", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, null, "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, null, "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, null, "", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, null, "", null, "");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, null, null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, null, null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, null, null, "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.TRUE, null, null, null, "foo");
////
//////////////////////////////////////////////
////      TRUE, DEFAULT, FALSE
////    
////      LOAD_EXTERNAL_DTD feature overrides ACCESS_EXTERNAL_DTD property.
//        
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "all", "all", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "all", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "all", "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "all", "all", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "all", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "all", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "all", "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "all", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "all", "", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "all", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "all", "", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "all", "", null, "");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "all", null, "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "all", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "all", null, "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "all", null, null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "jar,file", "all", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "jar,file", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "jar,file", "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "jar,file", "all", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "jar,file", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "jar,file", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "jar,file", "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "jar,file", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "jar,file", "", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "jar,file", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "jar,file", "", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "jar,file", "", null, "");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "jar,file", null, "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "jar,file", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "jar,file", null, "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "jar,file", null, null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "", "all", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "", "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "", "all", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "", "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "", "", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "", "", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "", "", null, "");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "", null, "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "", null, "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, "", null, null, "");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, null, "all", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, null, "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, null, "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, null, "all", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, null, "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, null, "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, null, "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, null, "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, null, "", "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, null, "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, null, "", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, null, "", null, "");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, null, null, "all", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, null, null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, null, null, "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.FALSE, null, null, null, ifValidating());
//// 
//////////////////////////////////////////////
////      TRUE, DEFAULT, DEFAULT
//    
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "all", "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "all", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "all", "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "all", "all", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "all", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "all", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "all", "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "all", "jar,file", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "all", "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "all", "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "all", "", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "all", "", null, "");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "all", null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "all", null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "all", null, "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "all", null, null, "foo");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "jar,file", "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "jar,file", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "jar,file", "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "jar,file", "all", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "jar,file", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "jar,file", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "jar,file", "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "jar,file", "jar,file", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "jar,file", "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "jar,file", "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "jar,file", "", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "jar,file", "", null, "");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "jar,file", null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "jar,file", null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "jar,file", null, "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "jar,file", null, null, "foo");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "", "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "", "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "", "all", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "", "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "", "jar,file", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "", "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "", "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "", "", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "", "", null, "");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "", null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "", null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "", null, "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, "", null, null, "");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, null, "all", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, null, "all", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, null, "all", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, null, "all", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, null, "jar,file", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, null, "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, null, "jar,file", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, null, "jar,file", null, "foo");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, null, "", "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, null, "", "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, null, "", "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, null, "", null, "");

        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, null, null, "all", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, null, null, "jar,file", "foo");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, null, null, "", "");
        doTestExternalDTD(type, E.TRUE, E.DEFAULT, E.DEFAULT, null, null, null, "foo");
////
//////////////////////////////////////////////
////      FALSE, TRUE, TRUE
////  
////      SECURE_PROCESSING_FEATURE = true and "jdk.xml.resolveExternalEntities" = false, so
////      ACCESS_EXTERNAL_DTD defaults to "".
//        
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "all", "all", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "all", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "all", "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "all", "all", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "all", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "all", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "all", "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "all", "jar,file", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "all", "", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "all", "", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "all", "", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "all", "", null, "");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "all", null, "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "all", null, "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "all", null, "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "all", null, null, "foo");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "jar,file", "all", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "jar,file", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "jar,file", "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "jar,file", "all", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "jar,file", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "jar,file", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "jar,file", "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "jar,file", "jar,file", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "jar,file", "", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "jar,file", "", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "jar,file", "", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "jar,file", "", null, "");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "jar,file", null, "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "jar,file", null, "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "jar,file", null, "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "jar,file", null, null, "foo");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "", "all", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "", "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "", "all", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "", "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "", "jar,file", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "", "", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "", "", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "", "", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "", "", null, "");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "", null, "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "", null, "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "", null, "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, "", null, null, "");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, null, "all", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, null, "all", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, null, "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, null, "all", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, null, "jar,file", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, null, "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, null, "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, null, "jar,file", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, null, "", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, null, "", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, null, "", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, null, "", null, "");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, null, null, "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, null, null, "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, null, null, "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.TRUE, null, null, null, "");
//
//////////////////////////////////////////////
////      FALSE, TRUE, FALSE
//    
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "all", "all", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "all", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "all", "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "all", "all", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "all", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "all", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "all", "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "all", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "all", "", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "all", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "all", "", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "all", "", null, "");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "all", null, "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "all", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "all", null, "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "all", null, null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "jar,file", "all", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "jar,file", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "jar,file", "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "jar,file", "all", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "jar,file", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "jar,file", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "jar,file", "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "jar,file", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "jar,file", "", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "jar,file", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "jar,file", "", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "jar,file", "", null, "");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "jar,file", null, "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "jar,file", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "jar,file", null, "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "jar,file", null, null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "", "all", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "", "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "", "all", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "", "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "", "", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "", "", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "", "", null, "");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "", null, "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "", null, "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, "", null, null, "");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, null, "all", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, null, "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, null, "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, null, "all", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, null, "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, null, "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, null, "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, null, "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, null, "", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, null, "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, null, "", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, null, "", null, "");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, null, null, "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, null, null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, null, null, "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.FALSE, null, null, null, "");
////
//////////////////////////////////////////////
////      FALSE, TRUE, DEFAULT
////        
////      SECURE_PROCESSING_FEATURE = true and "jdk.xml.resolveExternalEntities" = false, so
////      ACCESS_EXTERNAL_DTD defaults to "" and LOAD_EXTERNAL_DTD defaults to false.
//        
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "all", "all", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "all", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "all", "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "all", "all", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "all", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "all", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "all", "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "all", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "all", "", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "all", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "all", "", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "all", "", null, "");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "all", null, "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "all", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "all", null, "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "all", null, null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "jar,file", "all", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "jar,file", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "jar,file", "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "jar,file", "all", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "jar,file", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "jar,file", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "jar,file", "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "jar,file", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "jar,file", "", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "jar,file", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "jar,file", "", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "jar,file", "", null, "");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "jar,file", null, "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "jar,file", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "jar,file", null, "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "jar,file", null, null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "", "all", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "", "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "", "all", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "", "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "", "", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "", "", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "", "", null, "");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "", null, "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "", null, "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, "", null, null, "");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, null, "all", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, null, "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, null, "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, null, "all", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, null, "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, null, "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, null, "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, null, "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, null, "", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, null, "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, null, "", "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, null, "", null, "");

        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, null, null, "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, null, null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, null, null, "", "");
        doTestExternalDTD(type, E.FALSE, E.TRUE, E.DEFAULT, null, null, null, "");
////
//////////////////////////////////////////////
////      FALSE, FALSE, TRUE
////    
////      SECURE_PROCESSING_FEATURE is off, so the only property that is applied is the parser
////      factory / parser property.
//        
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "all", "all", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "all", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "all", "all", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "all", "all", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "all", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "all", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "all", "jar,file", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "all", "jar,file", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "all", "", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "all", "", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "all", "", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "all", "", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "all", null, "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "all", null, "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "all", null, "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "all", null, null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "jar,file", "all", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "jar,file", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "jar,file", "all", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "jar,file", "all", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "jar,file", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "jar,file", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "jar,file", "jar,file", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "jar,file", "jar,file", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "jar,file", "", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "jar,file", "", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "jar,file", "", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "jar,file", "", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "jar,file", null, "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "jar,file", null, "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "jar,file", null, "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "jar,file", null, null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "", "all", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "", "all", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "", "all", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "", "jar,file", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "", "jar,file", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "", "", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "", "", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "", "", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "", "", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "", null, "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "", null, "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "", null, "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, "", null, null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, null, "all", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, null, "all", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, null, "all", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, null, "all", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, null, "jar,file", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, null, "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, null, "jar,file", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, null, "jar,file", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, null, "", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, null, "", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, null, "", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, null, "", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, null, null, "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, null, null, "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, null, null, "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.TRUE, null, null, null, "foo");
////
//////////////////////////////////////////////
////      FALSE, FALSE, FALSE
////       
////    SECURE_PROCESSING_FEATURE is off, so the only property that is applied is the parser
////    factory / parser property.  LOAD_EXTERNAL_DTD = false overrides unless validating is on.
//    
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "all", "all", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "all", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "all", "all", "", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "all", "all", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "all", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "all", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "all", "jar,file", "", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "all", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "all", "", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "all", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "all", "", "", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "all", "", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "all", null, "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "all", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "all", null, "", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "all", null, null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "jar,file", "all", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "jar,file", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "jar,file", "all", "", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "jar,file", "all", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "jar,file", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "jar,file", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "jar,file", "jar,file", "", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "jar,file", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "jar,file", "", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "jar,file", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "jar,file", "", "", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "jar,file", "", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "jar,file", null, "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "jar,file", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "jar,file", null, "", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "jar,file", null, null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "", "all", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "", "all", "", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "", "all", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "", "jar,file", "", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "", "", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "", "", "", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "", "", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "", null, "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "", null, "", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, "", null, null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, null, "all", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, null, "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, null, "all", "", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, null, "all", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, null, "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, null, "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, null, "jar,file", "", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, null, "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, null, "", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, null, "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, null, "", "", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, null, "", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, null, null, "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, null, null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, null, null, "", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.FALSE, null, null, null, ifValidating());
////
////////////////////////////////////////////////
//////      FALSE, FALSE, DEFAULT
////    
////        When SECURE_PROCESSING_FEATURE is false
////        * the default value of LOAD_EXTERNAL_DTD is true
////        * the only property that is applied is the parser / parser factory property
////        * the default value for the parser / parser factory is "all"
////        
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "all", "all", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "all", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "all", "all", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "all", "all", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "all", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "all", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "all", "jar,file", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "all", "jar,file", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "all", "", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "all", "", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "all", "", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "all", "", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "all", null, "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "all", null, "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "all", null, "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "all", null, null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "jar,file", "all", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "jar,file", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "jar,file", "all", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "jar,file", "all", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "jar,file", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "jar,file", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "jar,file", "jar,file", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "jar,file", "jar,file", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "jar,file", "", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "jar,file", "", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "jar,file", "", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "jar,file", "", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "jar,file", null, "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "jar,file", null, "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "jar,file", null, "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "jar,file", null, null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "", "all", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "", "all", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "", "all", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "", "jar,file", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "", "jar,file", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "", "", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "", "", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "", "", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "", "", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "", null, "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "", null, "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "", null, "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, "", null, null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, null, "all", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, null, "all", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, null, "all", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, null, "all", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, null, "jar,file", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, null, "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, null, "jar,file", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, null, "jar,file", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, null, "", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, null, "", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, null, "", "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, null, "", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, null, null, "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, null, null, "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, null, null, "", "foo");
        doTestExternalDTD(type, E.FALSE, E.FALSE, E.DEFAULT, null, null, null, "foo");
//
//////////////////////////////////////////////
////      FALSE, DEFAULT, TRUE
////        
////      * RESOLVE_EXTERNAL_ENTITIES_SYSTEM_VALUE = false sets ACCESS_EXTERNAL_DTD factory property to "".
////      * Setting ACCESS_EXTERNAL_DTD factory property on the factory/parser overrides the default value of ""
////      * The SecurityManager property, if set, overrides all others.
////        
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "all", "all", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "all", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "all", "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "all", "all", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "all", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "all", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "all", "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "all", "jar,file", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "all", "", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "all", "", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "all", "", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "all", "", null, "");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "all", null, "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "all", null, "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "all", null, "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "all", null, null, "foo");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "jar,file", "all", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "jar,file", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "jar,file", "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "jar,file", "all", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "jar,file", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "jar,file", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "jar,file", "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "jar,file", "jar,file", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "jar,file", "", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "jar,file", "", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "jar,file", "", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "jar,file", "", null, "");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "jar,file", null, "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "jar,file", null, "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "jar,file", null, "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "jar,file", null, null, "foo");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "", "all", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "", "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "", "all", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "", "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "", "jar,file", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "", "", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "", "", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "", "", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "", "", null, "");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "", null, "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "", null, "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "", null, "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, "", null, null, "");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, null, "all", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, null, "all", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, null, "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, null, "all", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, null, "jar,file", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, null, "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, null, "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, null, "jar,file", null, "foo");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, null, "", "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, null, "", "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, null, "", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, null, "", null, "");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, null, null, "all", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, null, null, "jar,file", "foo");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, null, null, "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.TRUE, null, null, null, "");
////
//////////////////////////////////////////////
////      FALSE, DEFAULT, FALSE
////
////      * LOAD_EXTERNAL_DTD = false overrides, unless validating is on.
////        
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "all", "all", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "all", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "all", "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "all", "all", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "all", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "all", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "all", "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "all", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "all", "", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "all", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "all", "", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "all", "", null, "");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "all", null, "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "all", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "all", null, "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "all", null, null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "jar,file", "all", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "jar,file", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "jar,file", "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "jar,file", "all", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "jar,file", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "jar,file", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "jar,file", "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "jar,file", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "jar,file", "", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "jar,file", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "jar,file", "", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "jar,file", "", null, "");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "jar,file", null, "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "jar,file", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "jar,file", null, "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "jar,file", null, null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "", "all", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "", "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "", "all", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "", "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "", "", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "", "", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "", "", null, "");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "", null, "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "", null, "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, "", null, null, "");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, null, "all", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, null, "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, null, "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, null, "all", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, null, "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, null, "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, null, "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, null, "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, null, "", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, null, "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, null, "", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, null, "", null, "");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, null, null, "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, null, null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, null, null, "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.FALSE, null, null, null, "");
////
//////////////////////////////////////////////
////      FALSE, DEFAULT, DEFAULT
////
////      * RESOLVE_EXTERNAL_ENTITIES_SYSTEM_VALUE = false sets LOAD_EXTERNAL_DTD feature to false.
////        
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "all", "all", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "all", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "all", "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "all", "all", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "all", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "all", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "all", "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "all", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "all", "", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "all", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "all", "", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "all", "", null, "");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "all", null, "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "all", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "all", null, "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "all", null, null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "jar,file", "all", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "jar,file", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "jar,file", "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "jar,file", "all", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "jar,file", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "jar,file", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "jar,file", "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "jar,file", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "jar,file", "", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "jar,file", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "jar,file", "", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "jar,file", "", null, "");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "jar,file", null, "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "jar,file", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "jar,file", null, "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "jar,file", null, null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "", "all", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "", "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "", "all", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "", "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "", "", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "", "", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "", "", null, "");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "", null, "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "", null, "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, "", null, null, "");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, null, "all", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, null, "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, null, "all", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, null, "all", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, null, "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, null, "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, null, "jar,file", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, null, "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, null, "", "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, null, "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, null, "", "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, null, "", null, "");

        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, null, null, "all", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, null, null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, null, null, "", "");
        doTestExternalDTD(type, E.FALSE, E.DEFAULT, E.DEFAULT, null, null, null, "");
////
//////////////////////////////////////////////
////      DEFAULT, TRUE, TRUE
////        
////      * RESOLVE_EXTERNAL_ENTITIES_SYSTEM_VALUE defaults to false, which sets LOAD_EXTERNAL_DTD feature to false
////      * but LOAD_EXTERNAL_DTD = true set on parser / parser factory overrides.
//        
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "all", "all", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "all", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "all", "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "all", "all", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "all", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "all", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "all", "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "all", "jar,file", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "all", "", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "all", "", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "all", "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "all", "", null, "");
        
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "all", null, "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "all", null, "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "all", null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "all", null, null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "jar,file", "all", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "jar,file", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "jar,file", "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "jar,file", "all", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "jar,file", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "jar,file", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "jar,file", "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "jar,file", "jar,file", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "jar,file", "", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "jar,file", "", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "jar,file", "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "jar,file", "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "jar,file", null, "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "jar,file", null, "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "jar,file", null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "jar,file", null, null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "", "all", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "", "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "", "all", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "", "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "", "jar,file", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "", "", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "", "", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "", "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "", "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "", null, "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "", null, "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "", null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, "", null, null, "");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, null, "all", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, null, "all", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, null, "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, null, "all", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, null, "jar,file", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, null, "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, null, "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, null, "jar,file", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, null, "", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, null, "", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, null, "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, null, "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, null, null, "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, null, null, "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, null, null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.TRUE, null, null, null, "");
////
//////////////////////////////////////////////
////      DEFAULT, TRUE, FALSE
////
////      LOAD_EXTERNAL_DTD = false overrides.
//        
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "all", "all", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "all", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "all", "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "all", "all", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "all", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "all", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "all", "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "all", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "all", "", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "all", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "all", "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "all", "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "all", null, "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "all", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "all", null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "all", null, null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "jar,file", "all", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "jar,file", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "jar,file", "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "jar,file", "all", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "jar,file", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "jar,file", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "jar,file", "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "jar,file", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "jar,file", "", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "jar,file", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "jar,file", "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "jar,file", "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "jar,file", null, "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "jar,file", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "jar,file", null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "jar,file", null, null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "", "all", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "", "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "", "all", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "", "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "", "", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "", "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "", "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "", null, "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "", null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, "", null, null, "");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, null, "all", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, null, "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, null, "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, null, "all", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, null, "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, null, "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, null, "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, null, "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, null, "", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, null, "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, null, "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, null, "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, null, null, "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, null, null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, null, null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.FALSE, null, null, null, "");
////
//////////////////////////////////////////////
////      DEFAULT, TRUE, DEFAULT
////      
////      * RESOLVE_EXTERNAL_ENTITIES_SYSTEM_VALUE defaults to false, which sets LOAD_EXTERNAL_DTD feature to false.
//      
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "all", "all", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "all", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "all", "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "all", "all", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "all", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "all", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "all", "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "all", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "all", "", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "all", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "all", "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "all", "", null, "");
        
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "all", null, "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "all", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "all", null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "all", null, null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "jar,file", "all", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "jar,file", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "jar,file", "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "jar,file", "all", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "jar,file", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "jar,file", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "jar,file", "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "jar,file", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "jar,file", "", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "jar,file", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "jar,file", "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "jar,file", "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "jar,file", null, "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "jar,file", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "jar,file", null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "jar,file", null, null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "", "all", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "", "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "", "all", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "", "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "", "", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "", "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "", "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "", null, "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "", null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, "", null, null, "");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, null, "all", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, null, "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, null, "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, null, "all", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, null, "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, null, "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, null, "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, null, "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, null, "", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, null, "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, null, "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, null, "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, null, null, "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, null, null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, null, null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.TRUE, E.DEFAULT, null, null, null, "");
////
//////////////////////////////////////////////
////      DEFAULT, FALSE, TRUE
////        
////      * With SECURE_PROCESSING_FEATURE false, ACCESS_EXTERNAL_DTD defaults to "all".
////      * "javax.xml.accessExternalDTD" is ignored and there is no SecurityManager.
////      * The only property applied is the parser / parser factory property.
//        
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "all", "all", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "all", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "all", "all", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "all", "all", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "all", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "all", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "all", "jar,file", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "all", "jar,file", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "all", "", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "all", "", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "all", "", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "all", "", null, "foo");
        
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "all", null, "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "all", null, "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "all", null, "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "all", null, null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "jar,file", "all", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "jar,file", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "jar,file", "all", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "jar,file", "all", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "jar,file", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "jar,file", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "jar,file", "jar,file", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "jar,file", "jar,file", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "jar,file", "", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "jar,file", "", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "jar,file", "", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "jar,file", "", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "jar,file", null, "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "jar,file", null, "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "jar,file", null, "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "jar,file", null, null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "", "all", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "", "all", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "", "all", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "", "jar,file", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "", "jar,file", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "", "", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "", "", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "", "", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "", "", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "", null, "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "", null, "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "", null, "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, "", null, null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, null, "all", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, null, "all", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, null, "all", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, null, "all", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, null, "jar,file", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, null, "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, null, "jar,file", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, null, "jar,file", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, null, "", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, null, "", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, null, "", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, null, "", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, null, null, "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, null, null, "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, null, null, "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.TRUE, null, null, null, "foo");
////
//////////////////////////////////////////////
////      DEFAULT, FALSE, FALSE
////
////      LOAD_EXTERNAL_DTD = false overrides, even though there is no SecurityManager.
//        The only property applied is the parser / parser factory property.
//        The default value of ACCESS_EXTERNAL_DTD is "all".
//        
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "all", "all", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "all", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "all", "all", "", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "all", "all", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "all", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "all", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "all", "jar,file", "", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "all", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "all", "", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "all", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "all", "", "", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "all", "", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "all", null, "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "all", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "all", null, "", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "all", null, null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "jar,file", "all", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "jar,file", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "jar,file", "all", "", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "jar,file", "all", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "jar,file", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "jar,file", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "jar,file", "jar,file", "", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "jar,file", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "jar,file", "", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "jar,file", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "jar,file", "", "", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "jar,file", "", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "jar,file", null, "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "jar,file", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "jar,file", null, "", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "jar,file", null, null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "", "all", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "", "all", "", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "", "all", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "", "jar,file", "", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "", "", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "", "", "", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "", "", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "", null, "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "", null, "", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, "", null, null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, null, "all", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, null, "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, null, "all", "", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, null, "all", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, null, "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, null, "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, null, "jar,file", "", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, null, "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, null, "", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, null, "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, null, "", "", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, null, "", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, null, null, "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, null, null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, null, null, "", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.FALSE, null, null, null, ifValidating());
////
//////////////////////////////////////////////
////      DEFAULT, FALSE, DEFAULT
////
////      * With SECURE_PROCESSING_FEATURE false, ACCESS_EXTERNAL_DTD defaults to "all"
////        and LOAD_EXTERNAL_DTD defaults to true.
////      * The only property applied is the parser / parser factory property/
////
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "all", "all", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "all", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "all", "all", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "all", "all", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "all", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "all", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "all", "jar,file", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "all", "jar,file", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "all", "", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "all", "", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "all", "", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "all", "", null, "foo");
        
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "all", null, "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "all", null, "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "all", null, "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "all", null, null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "jar,file", "all", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "jar,file", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "jar,file", "all", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "jar,file", "all", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "jar,file", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "jar,file", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "jar,file", "jar,file", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "jar,file", "jar,file", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "jar,file", "", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "jar,file", "", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "jar,file", "", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "jar,file", "", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "jar,file", null, "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "jar,file", null, "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "jar,file", null, "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "jar,file", null, null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "", "all", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "", "all", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "", "all", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "", "jar,file", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "", "jar,file", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "", "", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "", "", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "", "", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "", "", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "", null, "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "", null, "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "", null, "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, "", null, null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, null, "all", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, null, "all", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, null, "all", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, null, "all", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, null, "jar,file", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, null, "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, null, "jar,file", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, null, "jar,file", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, null, "", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, null, "", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, null, "", "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, null, "", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, null, null, "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, null, null, "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, null, null, "", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.FALSE, E.DEFAULT, null, null, null, "foo");
////
//////////////////////////////////////////////
////      DEFAULT, DEFAULT, TRUE
////
////      SECURE_PROCESSING_FEATURE defaults to true and RESOLVE_EXTERNAL_ENTITIES_SYSTEM_VALUE defaults to false,
////      which sets ACCESS_EXTERNAL_DTD factory/parser property to "".
////        
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "all", "all", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "all", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "all", "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "all", "all", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "all", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "all", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "all", "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "all", "jar,file", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "all", "", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "all", "", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "all", "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "all", "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "all", null, "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "all", null, "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "all", null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "all", null, null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "jar,file", "all", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "jar,file", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "jar,file", "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "jar,file", "all", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "jar,file", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "jar,file", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "jar,file", "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "jar,file", "jar,file", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "jar,file", "", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "jar,file", "", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "jar,file", "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "jar,file", "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "jar,file", null, "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "jar,file", null, "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "jar,file", null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "jar,file", null, null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "", "all", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "", "all", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "", "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "", "all", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "", "jar,file", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "", "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "", "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "", "jar,file", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "", "", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "", "", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "", "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "", "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "", null, "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "", null, "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "", null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, "", null, null, "");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, null, "all", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, null, "all", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, null, "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, null, "all", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, null, "jar,file", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, null, "jar,file", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, null, "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, null, "jar,file", null, "foo");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, null, "", "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, null, "", "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, null, "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, null, "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, null, null, "all", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, null, null, "jar,file", "foo");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, null, null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.TRUE, null, null, null, "");
////
//////////////////////////////////////////////
////      DEFAULT, DEFAULT, FALSE
////
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "all", "all", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "all", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "all", "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "all", "all", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "all", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "all", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "all", "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "all", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "all", "", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "all", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "all", "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "all", "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "all", null, "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "all", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "all", null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "all", null, null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "jar,file", "all", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "jar,file", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "jar,file", "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "jar,file", "all", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "jar,file", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "jar,file", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "jar,file", "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "jar,file", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "jar,file", "", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "jar,file", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "jar,file", "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "jar,file", "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "jar,file", null, "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "jar,file", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "jar,file", null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "jar,file", null, null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "", "all", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "", "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "", "all", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "", "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "", "", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "", "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "", "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "", null, "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "", null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, "", null, null, "");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, null, "all", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, null, "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, null, "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, null, "all", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, null, "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, null, "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, null, "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, null, "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, null, "", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, null, "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, null, "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, null, "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, null, null, "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, null, null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, null, null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.FALSE, null, null, null, "");
////
//////////////////////////////////////////////
////      DEFAULT, DEFAULT, DEFAULT
////
////      * Same as FALSE, TRUE, FALSE
//        
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "all", "all", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "all", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "all", "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "all", "all", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "all", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "all", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "all", "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "all", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "all", "", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "all", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "all", "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "all", "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "all", null, "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "all", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "all", null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "all", null, null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "jar,file", "all", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "jar,file", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "jar,file", "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "jar,file", "all", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "jar,file", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "jar,file", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "jar,file", "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "jar,file", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "jar,file", "", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "jar,file", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "jar,file", "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "jar,file", "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "jar,file", null, "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "jar,file", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "jar,file", null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "jar,file", null, null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "", "all", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "", "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "", "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "", "all", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "", "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "", "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "", "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "", "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "", "", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "", "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "", "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "", "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "", null, "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "", null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "", null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, "", null, null, "");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, null, "all", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, null, "all", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, null, "all", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, null, "all", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, null, "jar,file", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, null, "jar,file", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, null, "jar,file", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, null, "jar,file", null, ifValidating());

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, null, "", "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, null, "", "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, null, "", "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, null, "", null, "");

        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, null, null, "all", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, null, null, "jar,file", ifValidating());
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, null, null, "", "");
        doTestExternalDTD(type, E.DEFAULT, E.DEFAULT, E.DEFAULT, null, null, null, "");
    }
    
    protected String ifValidating()
    {
        return validating() ? "foo" : "";
    }
    
    void doTestExternalDTD(ParserType type, E systemProperty, E secureProcessing, E loadExternalDTD, String systemProtocols, String factoryProtocols, String securityManagerProtocols, String expected) throws Exception
    {
        try
        {
            String text = doTestExternalDTDParse(type, systemProperty, secureProcessing, loadExternalDTD, systemProtocols, factoryProtocols, securityManagerProtocols, getExternalDTDWithInternalDTDDoc());
            debug("text: " + text);
            Assert.assertEquals(expected, text);
            
            text = doTestExternalDTDParse(type, systemProperty, secureProcessing, loadExternalDTD, systemProtocols, factoryProtocols, securityManagerProtocols, getExternalDTDWithoutInternalDTDDoc());
            debug("text: " + text);
            Assert.assertEquals(expected, text);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Wasn't expecting exception: " + e);
        }
    }
    
    String doTestExternalDTDParse(ParserType type, E systemProperty, E secureProcessing, E loadExternalDTD, String systemProtocols, String factoryProtocols, String securityManagerProtocols, String doc) throws Exception
    {
        try
        {
            if (!E.DEFAULT.equals(systemProperty))
            {
                System.setProperty(RESOLVE_EXTERNAL_ENTITIES_PROPERTY_NAME, systemProperty.toString());
            }
            if (systemProtocols != null)
            {
                System.setProperty(ACCESS_EXTERNAL_DTD_PROPERTY_NAME, systemProtocols);
            }
            ParserFactory factory = ParserFactory.newInstance(type);
            factory.setFeature(DISALLOW_DOCTYPE_DECL_FEATURE, false);
            factory.setFeature(NAMESPACES, namespaces());
            factory.setValidating(validating());
            if (!E.DEFAULT.equals(secureProcessing))
            {
                factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, secureProcessing.bool());
            }
            if (!E.DEFAULT.equals(loadExternalDTD))
            {
                factory.setFeature(LOAD_EXTERNAL_DTD_FEATURE, loadExternalDTD.bool());
            }
            if (factoryProtocols != null)
            {
                factory.setProperty(ACCESS_EXTERNAL_DTD_PROPERTY, factoryProtocols);
            }
            Parser parser = factory.newParser();
            if (securityManagerProtocols != null)
            {
                SecurityManager securityManager = (SecurityManager) parser.getProperty(SECURITY_MANAGER_PROPERTY);
                if (securityManager != null)
                {
                    securityManager.setAccessExternalDTD(securityManagerProtocols);
                }
            }
            ByteArrayInputStream baos = new ByteArrayInputStream(doc.getBytes());
            parser.parse(baos);
            return parser.getText();
        }
        finally
        {
            if (!E.DEFAULT.equals(systemProperty))
            {
                System.clearProperty(RESOLVE_EXTERNAL_ENTITIES_PROPERTY_NAME);
            }
            if (systemProtocols != null)
            {
                System.clearProperty(ACCESS_EXTERNAL_DTD_PROPERTY_NAME);
            }
        }
    }
    
    
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    //  Load external schema feature:
    //
    //  * jdk.xml.resolveExternalEntities"
    //  * javax.xml.accessExternalSchema
    //  * http://javax.xml.XMLConstants/property/accessExternalSchema
    //
    ////////////////////////////////////////////////////////////////////////////////////////////////////  
    
    // Notes.
    //
    // 1. There are several features and properties that determine if an external schema will be loaded.
    //
    //    a. SECURE_PROCESSING_FEATURE: When true, it imposes a number of property and feature restrictions. The default value
    //       of SECURE_PROCESSING_FEATURE is true.
    //
    //    b. RESOLVE_EXTERNAL_ENTITIES_PROPERTY property: It is relevant only when SECURE_PROCESSING_FEATURE is true.
    //       When set to false, it will, among other things, set the ACCESS_EXTERNAL_SCHEMA property to "", and when
    //       RESOLVE_EXTERNAL_ENTITIES_PROPERTY is true, the ACCESS_EXTERNAL_SCHEMA property is set to "all". See item c for a 
    //       discussion of ACCESS_EXTERNAL_SCHEMA. The default value of RESOLVE_EXTERNAL_ENTITIES_PROPERTY is false.
    //
    //    c. ACCESS_EXTERNAL_SCHEMA property: This property can be set to a comma separated list of protocols, e.g., "jar,file", by
    //       which schemas may be loaded. If SECURE_PROCESSING_FEATURE is false, ACCESS_EXTERNAL_DTD defaults to "all", meaning all
    //       protocols may be used. Otherwise, if SECURE_PROCESSING_FEATURE is true and RESOLVE_EXTERNAL_ENTITIES_PROPERTY is false,
    //       ACCESS_EXTERNAL_DTD defaults to "", meaning no protocols may be used.
    //
    //       As with many security related properties, ACCESS_EXTERNAL_SCHEMA may, if SECURE_PROCESSING_FEATURE is true,
    //       be set in several ways:
    //
    //       i. "javax.xml.accessExternalSchema" system property
    //      ii. "http://javax.xml.XMLConstants/property/accessExternalSchema" parser / parser factory property
    //     iii. SecurityManager.setAccessExternalSchema()
    //
    
    @Test
    public void testExternalSchema() throws Exception
    {
        doTestExternalSchema(ParserType.SAX);
        doTestExternalSchema(ParserType.DOM);
    }
    
    void doTestExternalSchema(ParserType type) throws Exception
    {
//
////////////////////////////////////////////
//      TRUE, TRUE
//
//                                        jdk.xml.resolveExternalEntities
//                                        |       http://javax.xml.XMLConstants/feature/secure-processing
//                                        |       |       system property
//                                        |       |       |      factory property
//                                        |       |       |      |      security manager property
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "all", "all", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "all", "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.TRUE, "all", "all", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "all", "all", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "all", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "all", "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.TRUE, "all", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "all", "jar,file", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "all", "", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "all", "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.TRUE, "all", "", "");
        doTestsExternalSchemaFails(type,  E.TRUE, E.TRUE, "all", "", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "all", null, "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "all", null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.TRUE, "all", null, "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "all", null, null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "jar,file", "all", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "jar,file", "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.TRUE, "jar,file", "all", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "jar,file", "all", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "jar,file", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "jar,file", "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.TRUE, "jar,file", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "jar,file", "jar,file", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "jar,file", "", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "jar,file", "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.TRUE, "jar,file", "", "");
        doTestsExternalSchemaFails(type,  E.TRUE, E.TRUE, "jar,file", "", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "jar,file", null, "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "jar,file", null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.TRUE, "jar,file", null, "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "jar,file", null, null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "", "all", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "", "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.TRUE, "", "all", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "", "all", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "", "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.TRUE, "", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "", "jar,file", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "", "", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "", "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.TRUE, "", "", "");
        doTestsExternalSchemaFails(type,  E.TRUE, E.TRUE, "", "", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "", null, "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, "", null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.TRUE, "", null, "");
        doTestsExternalSchemaFails(type,  E.TRUE, E.TRUE, "", null, null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, null, "all", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, null, "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.TRUE, null, "all", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, null, "all", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, null, "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, null, "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.TRUE, null, "jar,file", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, null, "jar,file", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, null, "", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, null, "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.TRUE, null, "", "");
        doTestsExternalSchemaFails(type,  E.TRUE, E.TRUE, null, "", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, null, null, "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, null, null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.TRUE, null, null, "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.TRUE, null, null, null);
//
////////////////////////////////////////////
//      TRUE, FALSE
//        
//      SECURE_PROCESSING_FEATURE is off, so ACCESS_EXTERNAL_SCHEMA is set to "all".
//
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "all", "all", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "all", "all", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "all", "all", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "all", "all", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "all", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "all", "jar,file", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "all", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "all", "jar,file", null);

        doTestsExternalSchemaPasses(type,  E.TRUE, E.FALSE, "all", "", "all");
        doTestsExternalSchemaPasses(type,  E.TRUE, E.FALSE, "all", "", "jar,file"); 
        doTestsExternalSchemaPasses(type,  E.TRUE, E.FALSE, "all", "", "");
        doTestsExternalSchemaPasses(type,  E.TRUE, E.FALSE, "all", "", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "all", null, "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "all", null, "jar,file"); 
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "all", null, "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "all", null, null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "jar,file", "all", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "jar,file", "all", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "jar,file", "all", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "jar,file", "all", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "jar,file", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "jar,file", "jar,file", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "jar,file", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "jar,file", "jar,file", null);

        doTestsExternalSchemaPasses(type,  E.TRUE, E.FALSE, "jar,file", "", "all");
        doTestsExternalSchemaPasses(type,  E.TRUE, E.FALSE, "jar,file", "", "jar,file"); 
        doTestsExternalSchemaPasses(type,  E.TRUE, E.FALSE, "jar,file", "", "");
        doTestsExternalSchemaPasses(type,  E.TRUE, E.FALSE, "jar,file", "", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "jar,file", null, "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "jar,file", null, "jar,file"); 
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "jar,file", null, "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "jar,file", null, null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "", "all", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "", "all", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "", "all", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "", "all", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "", "jar,file", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, "", "jar,file", null);

        doTestsExternalSchemaPasses(type,  E.TRUE, E.FALSE, "", "", "all");
        doTestsExternalSchemaPasses(type,  E.TRUE, E.FALSE, "", "", "jar,file"); 
        doTestsExternalSchemaPasses(type,  E.TRUE, E.FALSE, "", "", "");
        doTestsExternalSchemaPasses(type,  E.TRUE, E.FALSE, "", "", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, null, "all", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, null, "all", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, null, "all", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, null, "all", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, null, "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, null, "jar,file", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, null, "jar,file", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, null, "jar,file", null);

        doTestsExternalSchemaPasses(type,  E.TRUE, E.FALSE, null, "", "all");
        doTestsExternalSchemaPasses(type,  E.TRUE, E.FALSE, null, "", "jar,file"); 
        doTestsExternalSchemaPasses(type,  E.TRUE, E.FALSE, null, "", "");
        doTestsExternalSchemaPasses(type,  E.TRUE, E.FALSE, null, "", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, null, null, "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, null, null, "jar,file"); 
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, null, null, "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.FALSE, null, null, null);
//        
////////////////////////////////////////////
//      TRUE, FALSE
//      
//    Same as TRUE, TRUE
//
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "all", "all", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "all", "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.DEFAULT, "all", "all", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "all", "all", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "all", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "all", "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.DEFAULT, "all", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "all", "jar,file", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "all", "", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "all", "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.DEFAULT, "all", "", "");
        doTestsExternalSchemaFails(type,  E.TRUE, E.DEFAULT, "all", "", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "all", null, "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "all", null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.DEFAULT, "all", null, "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "all", null, null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "jar,file", "all", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "jar,file", "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.DEFAULT, "jar,file", "all", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "jar,file", "all", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "jar,file", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "jar,file", "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.DEFAULT, "jar,file", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "jar,file", "jar,file", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "jar,file", "", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "jar,file", "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.DEFAULT, "jar,file", "", "");
        doTestsExternalSchemaFails(type,  E.TRUE, E.DEFAULT, "jar,file", "", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "jar,file", null, "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "jar,file", null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.DEFAULT, "jar,file", null, "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "jar,file", null, null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "", "all", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "", "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.DEFAULT, "", "all", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "", "all", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "", "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.DEFAULT, "", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "", "jar,file", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "", "", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "", "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.DEFAULT, "", "", "");
        doTestsExternalSchemaFails(type,  E.TRUE, E.DEFAULT, "", "", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "", null, "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, "", null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.DEFAULT, "", null, "");
        doTestsExternalSchemaFails(type,  E.TRUE, E.DEFAULT, "", null, null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, null, "all", "all"); 
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, null, "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.DEFAULT, null, "all", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, null, "all", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, null, "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, null, "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.DEFAULT, null, "jar,file", "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, null, "jar,file", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, null, "", "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, null, "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.DEFAULT, null, "", "");
        doTestsExternalSchemaFails(type,  E.TRUE, E.DEFAULT, null, "", null);

        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, null, null, "all");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, null, null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.TRUE, E.DEFAULT, null, null, "");
        doTestsExternalSchemaPasses(type, E.TRUE, E.DEFAULT, null, null, null);
//      
////////////////////////////////////////////
//      FALSE, TRUE
//
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "all", "all", "all"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "all", "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, "all", "all", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "all", "all", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "all", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "all", "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, "all", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "all", "jar,file", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "all", "", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "all", "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, "all", "", "");
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, "all", "", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "all", null, "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "all", null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, "all", null, "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "all", null, null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "jar,file", "all", "all"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "jar,file", "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, "jar,file", "all", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "jar,file", "all", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "jar,file", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "jar,file", "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, "jar,file", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "jar,file", "jar,file", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "jar,file", "", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "jar,file", "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, "jar,file", "", "");
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, "jar,file", "", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "jar,file", null, "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "jar,file", null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, "jar,file", null, "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "jar,file", null, null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "", "all", "all"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "", "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, "", "all", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "", "all", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "", "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, "", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "", "jar,file", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "", "", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "", "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, "", "", "");
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, "", "", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "", null, "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, "", null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, "", null, "");
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, "", null, null);
  
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, null, "all", "all"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, null, "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, null, "all", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, null, "all", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, null, "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, null, "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, null, "jar,file", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, null, "jar,file", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, null, "", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, null, "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, null, "", "");
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, null, "", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, null, null, "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.TRUE, null, null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, null, null, "");
        doTestsExternalSchemaFails(type,  E.FALSE, E.TRUE, null, null, null);
//      
////////////////////////////////////////////
//      FALSE, FALSE
//
//      SECURE_PROCESSING_FEATURE is off, so ACCESS_EXTERNAL_SCHEMA is set to "all".
//
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "all", "all", "all"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "all", "all", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "all", "all", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "all", "all", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "all", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "all", "jar,file", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "all", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "all", "jar,file", null);

        doTestsExternalSchemaPasses(type,  E.FALSE, E.FALSE, "all", "", "all");
        doTestsExternalSchemaPasses(type,  E.FALSE, E.FALSE, "all", "", "jar,file"); 
        doTestsExternalSchemaPasses(type,  E.FALSE, E.FALSE, "all", "", "");
        doTestsExternalSchemaPasses(type,  E.FALSE, E.FALSE, "all", "", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "all", null, "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "all", null, "jar,file"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "all", null, "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "all", null, null);
        
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "jar,file", "all", "all"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "jar,file", "all", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "jar,file", "all", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "jar,file", "all", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "jar,file", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "jar,file", "jar,file", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "jar,file", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "jar,file", "jar,file", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "jar,file", "", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "jar,file", "", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "jar,file", "", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "jar,file", "", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "jar,file", null, "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "jar,file", null, "jar,file"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "jar,file", null, "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "jar,file", null, null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "", "all", "all"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "", "all", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "", "all", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "", "all", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "", "jar,file", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "", "jar,file", null);

        doTestsExternalSchemaPasses(type,  E.FALSE, E.FALSE, "", "", "all");
        doTestsExternalSchemaPasses(type,  E.FALSE, E.FALSE, "", "", "jar,file"); 
        doTestsExternalSchemaPasses(type,  E.FALSE, E.FALSE, "", "", "");
        doTestsExternalSchemaPasses(type,  E.FALSE, E.FALSE, "", "", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "", null, "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "", null, "jar,file"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "", null, "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, "", null, null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, null, "all", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, null, "all", "jar,file");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, null, "all", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, null, "all", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, null, "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, null, "jar,file", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, null, "jar,file", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, null, "jar,file", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, null, "", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, null, "", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, null, "", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, null, "", null);

      // No SecurityManager, no SecureProcessingConfiguration to read value of
      // system property "jdk.xml.resolveExternalEntities",
      // "http://javax.xml.XMLConstants/property/accessExternalSchema" property
      // is not set on parser/parser factory, and default value is "all".
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, null, null, "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, null, null, "jar,file"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, null, null, "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.FALSE, null, null, null);
//      
////////////////////////////////////////////
//      FALSE, DEFAULT
// 
//      Same as FALSE, TRUE
//        
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "all", "all", "all"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "all", "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, "all", "all", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "all", "all", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "all", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "all", "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, "all", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "all", "jar,file", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "all", "", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "all", "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, "all", "", "");
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, "all", "", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "all", null, "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "all", null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, "all", null, "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "all", null, null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "jar,file", "all", "all"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "jar,file", "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, "jar,file", "all", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "jar,file", "all", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "jar,file", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "jar,file", "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, "jar,file", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "jar,file", "jar,file", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "jar,file", "", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "jar,file", "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, "jar,file", "", "");
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, "jar,file", "", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "jar,file", null, "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "jar,file", null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, "jar,file", null, "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "jar,file", null, null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "", "all", "all"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "", "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, "", "all", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "", "all", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "", "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, "", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "", "jar,file", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "", "", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "", "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, "", "", "");
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, "", "", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "", null, "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, "", null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, "", null, "");
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, "", null, null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, null, "all", "all"); 
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, null, "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, null, "all", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, null, "all", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, null, "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, null, "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, null, "jar,file", "");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, null, "jar,file", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, null, "", "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, null, "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, null, "", "");
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, null, "", null);

        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, null, null, "all");
        doTestsExternalSchemaPasses(type, E.FALSE, E.DEFAULT, null, null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, null, null, "");
        doTestsExternalSchemaFails(type,  E.FALSE, E.DEFAULT, null, null, null);
//      
////////////////////////////////////////////
//      FALSE, DEFAULT
//
//      Same as TRUE, TRUE
//
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "all", "all", "all"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "all", "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, "all", "all", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "all", "all", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "all", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "all", "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, "all", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "all", "jar,file", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "all", "", "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "all", "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, "all", "", "");
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, "all", "", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "all", null, "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "all", null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, "all", null, "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "all", null, null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "jar,file", "all", "all"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "jar,file", "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, "jar,file", "all", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "jar,file", "all", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "jar,file", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "jar,file", "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, "jar,file", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "jar,file", "jar,file", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "jar,file", "", "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "jar,file", "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, "jar,file", "", "");
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, "jar,file", "", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "jar,file", null, "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "jar,file", null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, "jar,file", null, "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "jar,file", null, null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "", "all", "all"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "", "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, "", "all", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "", "all", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "", "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, "", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "", "jar,file", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "", "", "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "", "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, "", "", "");
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, "", "", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "", null, "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, "", null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, "", null, "");
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, "", null, null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, null, "all", "all"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, null, "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, null, "all", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, null, "all", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, null, "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, null, "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, null, "jar,file", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, null, "jar,file", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, null, "", "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, null, "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, null, "", "");
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, null, "", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, null, null, "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.TRUE, null, null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, null, null, "");
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.TRUE, null, null, null);
//      
////////////////////////////////////////////
//      DEFAULT, FALSE
//
//      SECURE_PROCESSING_FEATURE is off, so ACCESS_EXTERNAL_SCHEMA is set to "all".
//
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "all", "all", "all"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "all", "all", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "all", "all", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "all", "all", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "all", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "all", "jar,file", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "all", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "all", "jar,file", null);

        doTestsExternalSchemaPasses(type,  E.DEFAULT, E.FALSE, "all", "", "all");
        doTestsExternalSchemaPasses(type,  E.DEFAULT, E.FALSE, "all", "", "jar,file"); 
        doTestsExternalSchemaPasses(type,  E.DEFAULT, E.FALSE, "all", "", "");
        doTestsExternalSchemaPasses(type,  E.DEFAULT, E.FALSE, "all", "", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "all", null, "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "all", null, "jar,file"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "all", null, "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "all", null, null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "jar,file", "all", "all"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "jar,file", "all", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "jar,file", "all", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "jar,file", "all", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "jar,file", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "jar,file", "jar,file", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "jar,file", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "jar,file", "jar,file", null);

        doTestsExternalSchemaPasses(type,  E.DEFAULT, E.FALSE, "jar,file", "", "all");
        doTestsExternalSchemaPasses(type,  E.DEFAULT, E.FALSE, "jar,file", "", "jar,file"); 
        doTestsExternalSchemaPasses(type,  E.DEFAULT, E.FALSE, "jar,file", "", "");
        doTestsExternalSchemaPasses(type,  E.DEFAULT, E.FALSE, "jar,file", "", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "jar,file", null, "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "jar,file", null, "jar,file"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "jar,file", null, "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "jar,file", null, null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "", "all", "all"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "", "all", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "", "all", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "", "all", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "", "jar,file", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "", "jar,file", null);

        doTestsExternalSchemaPasses(type,  E.DEFAULT, E.FALSE, "", "", "all");
        doTestsExternalSchemaPasses(type,  E.DEFAULT, E.FALSE, "", "", "jar,file"); 
        doTestsExternalSchemaPasses(type,  E.DEFAULT, E.FALSE, "", "", "");
        doTestsExternalSchemaPasses(type,  E.DEFAULT, E.FALSE, "", "", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "", null, "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "", null, "jar,file"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "", null, "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, "", null, null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, null, "all", "all"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, null, "all", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, null, "all", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, null, "all", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, null, "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, null, "jar,file", "jar,file"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, null, "jar,file", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, null, "jar,file", null);

        doTestsExternalSchemaPasses(type,  E.DEFAULT, E.FALSE, null, "", "all");
        doTestsExternalSchemaPasses(type,  E.DEFAULT, E.FALSE, null, "", "jar,file"); 
        doTestsExternalSchemaPasses(type,  E.DEFAULT, E.FALSE, null, "", "");
        doTestsExternalSchemaPasses(type,  E.DEFAULT, E.FALSE, null, "", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, null, null, "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, null, null, "jar,file"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, null, null, "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.FALSE, null, null, null);
//      
////////////////////////////////////////////
//      DEFAULT, DEFAULT
//
//      Same as TRUE, TRUE
//
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "all", "all", "all"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "all", "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, "all", "all", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "all", "all", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "all", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "all", "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, "all", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "all", "jar,file", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "all", "", "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "all", "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, "all", "", "");
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, "all", "", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "all", null, "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "all", null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, "all", null, "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "all", null, null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "jar,file", "all", "all"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "jar,file", "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, "jar,file", "all", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "jar,file", "all", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "jar,file", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "jar,file", "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, "jar,file", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "jar,file", "jar,file", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "jar,file", "", "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "jar,file", "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, "jar,file", "", "");
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, "jar,file", "", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "jar,file", null, "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "jar,file", null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, "jar,file", null, "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "jar,file", null, null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "", "all", "all"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "", "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, "", "all", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "", "all", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "", "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "", "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, "", "jar,file", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "", "jar,file", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "", "", "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "", "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, "", "", "");
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, "", "", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "", null, "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, "", null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, "", null, "");
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, "", null, null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, null, "all", "all"); 
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, null, "all", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, null, "all", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, null, "all", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, null, "jar,file", "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, null, "jar,file", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, null, "jar,file", "");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, null, "jar,file", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, null, "", "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, null, "", "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, null, "", "");
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, null, "", null);

        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, null, null, "all");
        doTestsExternalSchemaPasses(type, E.DEFAULT, E.DEFAULT, null, null, "jar,file"); 
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, null, null, "");
        doTestsExternalSchemaFails(type,  E.DEFAULT, E.DEFAULT, null, null, null);
    }
    
    void doTestsExternalSchemaPasses(ParserType type, E systemProperty, E secureProcessing, String systemProtocols, String factoryProtocols, String securityManagerProtocols) throws Exception
    {
        try
        {
            doTestExternalSchemaParse(type, secureProcessing, systemProperty, systemProtocols, factoryProtocols, securityManagerProtocols, getExternalSchemaDoc());
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Wasn't expecting exception: " + e);
        }
    }

    void doTestsExternalSchemaFails(ParserType type, E systemProperty, E secureProcessing, String systemProtocols, String factoryProtocols, String securityManagerProtocols) throws Exception
    {
        try
        {
            doTestExternalSchemaParse(type, secureProcessing, systemProperty, systemProtocols, factoryProtocols, securityManagerProtocols, getExternalSchemaDoc());
            fail("Expecting exception");
        }
        catch (SAXParseException e)
        {
            debug(e.getMessage());
            Assert.assertTrue(e.getMessage().contains("Failed to read schema document \"foo"));
            Assert.assertTrue(e.getMessage().contains(".xsd\", because \"file\" access is not allowed due to restriction set by the accessExternalSchema property."));
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Expecting SAXParseException, not " + e);
        }
    }
    
    void doTestExternalSchemaParse(ParserType type, E secureProcessing, E systemProperty, String systemProtocols, String factoryProtocols, String securityManagerProtocols, String file) throws Exception
    {
        try
        {
            if (!E.DEFAULT.equals(systemProperty))
            {
                System.setProperty(RESOLVE_EXTERNAL_ENTITIES_PROPERTY_NAME, systemProperty.toString());
            }
            if (systemProtocols != null)
            {
                System.setProperty(ACCESS_EXTERNAL_SCHEMA_PROPERTY_NAME, systemProtocols);
            }
            ParserFactory factory = ParserFactory.newInstance(type);
            factory.setValidating(true);
            factory.setNamespaceAware(true);
            factory.setFeature(NAMESPACES, true);
            factory.setProperty(JAXPConstants.JAXP_SCHEMA_LANGUAGE, XMLConstants.W3C_XML_SCHEMA_NS_URI);
            if (!E.DEFAULT.equals(secureProcessing))
            {
                factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, secureProcessing.bool());
            }
            if (factoryProtocols != null)
            {
                factory.setProperty(ACCESS_EXTERNAL_SCHEMA_PROPERTY, factoryProtocols);
            }
            Parser parser = factory.newParser();
            if (securityManagerProtocols != null)
            {
                SecurityManager securityManager = (SecurityManager) parser.getProperty(SECURITY_MANAGER_PROPERTY);
                if (securityManager != null)
                {
                    securityManager.setAccessExternalSchema(securityManagerProtocols);
                }
            }
            ByteArrayInputStream baos = new ByteArrayInputStream(file.getBytes());
            parser.parse(baos);
        }
        finally
        {
            if (!E.DEFAULT.equals(systemProperty))
            {
                System.clearProperty(RESOLVE_EXTERNAL_ENTITIES_PROPERTY_NAME);
            }
            if (systemProtocols != null)
            {
                System.clearProperty(ACCESS_EXTERNAL_SCHEMA_PROPERTY_NAME);
            }
        }   
    }


    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    //  total entity size limit:
    //
    //  * jdk.xml.totalEntitySizeLimit
    //  * http://www.oracle.com/xml/jaxp/properties/totalEntitySizeLimi
    //
    //////////////////////////////////////////////////////////////////////////////////////////////////// 
    
    @Test
    public void testTotalEntitySizeLimit() throws Exception
    {
        doTestTotalEntitySizeLimit(ParserType.SAX);
        doTestTotalEntitySizeLimit(ParserType.DOM);
    }

    void doTestTotalEntitySizeLimit(ParserType type) throws Exception
    {
//                                             secure processing feature
//                                             |        system property limit
//                                             |        |   factory property limit
//                                             |        |   |  security manager limit
//                                             |        |   |  |   expected limit
        doTestTotalEntitySizeLimitFails(type,  E.TRUE,  3,  5,  7, "7");
        doTestTotalEntitySizeLimitPasses(type, E.TRUE,  3,  5,  0);
        doTestTotalEntitySizeLimitFails(type,  E.TRUE,  3,  5, -1, "5");
        doTestTotalEntitySizeLimitFails(type,  E.TRUE,  3,  0,  7, "7");
        doTestTotalEntitySizeLimitPasses(type, E.TRUE,  3,  0,  0);
        doTestTotalEntitySizeLimitPasses(type, E.TRUE,  3,  0, -1);
        doTestTotalEntitySizeLimitFails(type,  E.TRUE,  3, -1,  7, "7");
        doTestTotalEntitySizeLimitPasses(type, E.TRUE,  3, -1,  0);
        doTestTotalEntitySizeLimitFails(type,  E.TRUE,  3, -1, -1, "3");
        
        doTestTotalEntitySizeLimitFails(type,  E.TRUE,  0,  5,  7, "7");
        doTestTotalEntitySizeLimitPasses(type, E.TRUE,  0,  5,  0);
        doTestTotalEntitySizeLimitFails(type,  E.TRUE,  0,  5, -1, "5");
        doTestTotalEntitySizeLimitFails(type,  E.TRUE,  0,  0,  7, "7");
        doTestTotalEntitySizeLimitPasses(type, E.TRUE,  0,  0,  0);
        doTestTotalEntitySizeLimitPasses(type, E.TRUE,  0,  0, -1);
        doTestTotalEntitySizeLimitFails(type,  E.TRUE,  0, -1,  7, "7");
        doTestTotalEntitySizeLimitPasses(type, E.TRUE,  0, -1,  0);
        doTestTotalEntitySizeLimitPasses(type, E.TRUE,  0, -1, -1);

        doTestTotalEntitySizeLimitFails(type,  E.TRUE, -1,  5,  7, "7");
        doTestTotalEntitySizeLimitPasses(type, E.TRUE, -1,  5,  0);
        doTestTotalEntitySizeLimitFails(type,  E.TRUE, -1,  5, -1, "5");
        doTestTotalEntitySizeLimitFails(type,  E.TRUE, -1,  0,  7, "7");
        doTestTotalEntitySizeLimitPasses(type, E.TRUE, -1,  0,  0);
        doTestTotalEntitySizeLimitPasses(type, E.TRUE, -1,  0, -1);
        doTestTotalEntitySizeLimitFails(type,  E.TRUE, -1, -1,  7, "7");
        doTestTotalEntitySizeLimitPasses(type, E.TRUE, -1, -1,  0);
        doTestTotalEntitySizeLimitPasses(type, E.TRUE, -1, -1, -1);
        
        doTestTotalEntitySizeLimitPasses(type, E.FALSE,  3,  5,  7);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE,  3,  5,  0);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE,  3,  5, -1);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE,  3,  0,  7);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE,  3,  0,  0);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE,  3,  0, -1);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE,  3, -1,  7);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE,  3, -1,  0);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE,  3, -1, -1);
        
        doTestTotalEntitySizeLimitPasses(type, E.FALSE,  0,  5,  7);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE,  0,  5,  0);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE,  0,  5, -1);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE,  0,  0,  7);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE,  0,  0,  0);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE,  0,  0, -1);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE,  0, -1,  7);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE,  0, -1,  0);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE,  0, -1, -1);

        doTestTotalEntitySizeLimitPasses(type, E.FALSE, -1,  5,  7);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE, -1,  5,  0);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE, -1,  5, -1);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE, -1,  0,  7);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE, -1,  0,  0);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE, -1,  0, -1);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE, -1, -1,  7);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE, -1, -1,  0);
        doTestTotalEntitySizeLimitPasses(type, E.FALSE, -1, -1, -1);
        
        doTestTotalEntitySizeLimitFails(type,  E.DEFAULT,  3,  5,  7, "7");
        doTestTotalEntitySizeLimitPasses(type, E.DEFAULT,  3,  5,  0);
        doTestTotalEntitySizeLimitFails(type,  E.DEFAULT,  3,  5, -1, "5");
        doTestTotalEntitySizeLimitFails(type,  E.DEFAULT,  3,  0,  7, "7");
        doTestTotalEntitySizeLimitPasses(type, E.DEFAULT,  3,  0,  0);
        doTestTotalEntitySizeLimitPasses(type, E.DEFAULT,  3,  0, -1);
        doTestTotalEntitySizeLimitFails(type,  E.DEFAULT,  3, -1,  7, "7");
        doTestTotalEntitySizeLimitPasses(type, E.DEFAULT,  3, -1,  0);
        doTestTotalEntitySizeLimitFails(type,  E.DEFAULT,  3, -1, -1, "3");
        
        doTestTotalEntitySizeLimitFails(type,  E.DEFAULT,  0,  5,  7, "7");
        doTestTotalEntitySizeLimitPasses(type, E.DEFAULT,  0,  5,  0);
        doTestTotalEntitySizeLimitFails(type,  E.DEFAULT,  0,  5, -1, "5");
        doTestTotalEntitySizeLimitFails(type,  E.DEFAULT,  0,  0,  7, "7");
        doTestTotalEntitySizeLimitPasses(type, E.DEFAULT,  0,  0,  0);
        doTestTotalEntitySizeLimitPasses(type, E.DEFAULT,  0,  0, -1);
        doTestTotalEntitySizeLimitFails(type,  E.DEFAULT,  0, -1,  7, "7");
        doTestTotalEntitySizeLimitPasses(type, E.DEFAULT,  0, -1,  0);
        doTestTotalEntitySizeLimitPasses(type, E.DEFAULT,  0, -1, -1);

        doTestTotalEntitySizeLimitFails(type,  E.DEFAULT, -1,  5,  7, "7");
        doTestTotalEntitySizeLimitPasses(type, E.DEFAULT, -1,  5,  0);
        doTestTotalEntitySizeLimitFails(type,  E.DEFAULT, -1,  5, -1, "5");
        doTestTotalEntitySizeLimitFails(type,  E.DEFAULT, -1,  0,  7, "7");
        doTestTotalEntitySizeLimitPasses(type, E.DEFAULT, -1,  0,  0);
        doTestTotalEntitySizeLimitPasses(type, E.DEFAULT, -1,  0, -1);
        doTestTotalEntitySizeLimitFails(type,  E.DEFAULT, -1, -1,  7, "7");
        doTestTotalEntitySizeLimitPasses(type, E.DEFAULT, -1, -1,  0);
        doTestTotalEntitySizeLimitPasses(type, E.DEFAULT, -1, -1, -1);
    }

    void doTestTotalEntitySizeLimitPasses(ParserType type, E secureProcessing, int systemLimit, int factoryLimit, int securityLimit)
    {
        try
        {
            doTestTotalEntitySizeLimitParse(type, secureProcessing, systemLimit, factoryLimit, securityLimit); 
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Wasn't expecting exception: " + e);
        }
    }

    void doTestTotalEntitySizeLimitFails(ParserType type, E secureProcessing, int systemLimit, int factoryLimit, int securityLimit, String expected)
    {
        try
        {
            doTestTotalEntitySizeLimitParse(type, secureProcessing, systemLimit, factoryLimit, securityLimit);
            fail("Expecting SAXParseException");
        }
        catch (SAXParseException e)
        {
            debug(e);
            Assert.assertTrue(e.getMessage().contains("The parser has encountered more than \"" + expected + "\" bytes or characters within entities declared and referenced by this document; this is the limit imposed by the application."));
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Expecting SAXParseException");
        }
    }    

    void doTestTotalEntitySizeLimitParse(ParserType type, E secureProcessing, int systemLimit, int factoryLimit, int securityLimit) throws Exception
    {
        try
        {
            if (systemLimit >= 0)
            {
                System.setProperty(TOTAL_ENTITY_SIZE_LIMIT_PROPERTY_NAME, Integer.toString(systemLimit));
            }
            ParserFactory factory = ParserFactory.newInstance(type);
            factory.setFeature(DISALLOW_DOCTYPE_DECL_FEATURE, false);
            if (!E.DEFAULT.equals(secureProcessing))
            {
                factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, secureProcessing.bool());
            }
            factory.setFeature(NAMESPACES, namespaces());
            factory.setValidating(validating());
            Parser parser = factory.newParser();
            if (factoryLimit >= 0)
            {
                parser.setProperty(MAX_TOTAL_ENTITY_SIZE_LIMIT, factoryLimit);
            }
            if (securityLimit >= 0)
            {
                SecurityManager sm = (SecurityManager) parser.getProperty(SECURITY_MANAGER_PROPERTY);
                if (sm != null)
                {
                    sm.setTotalEntitySizeLimit(securityLimit);
                }
            }
            TestErrorHandler errorHandler = new TestErrorHandler();
            parser.setErrorHandler(errorHandler);
            ByteArrayInputStream baos = new ByteArrayInputStream(getTotalEntitySizeDoc().getBytes(Charset.forName("UTF-8")));
            parser.parse(baos);
        }
        finally
        {
            if (systemLimit >= 0)
            {
                System.setProperty(TOTAL_ENTITY_SIZE_LIMIT_PROPERTY_NAME, "");
            }
        }
    }
    
    
    /////////////////////////////////////////////////////////////////////////////////////////
    //
    //  general and parameter entity size limit
    //
    //  * jdk.xml.maxGeneralEntitySizeLimit
    //  * jdk.xml.maxParameterEntitySizeLimit
    //  * http://java.sun.com/xml/jaxp/properties/maxGeneralEntitySizeLimit
    //  * http://www.oracle.com/xml/jaxp/properties/maxGeneralEntitySizeLimit
    //  * http://www.oracle.com/xml/jaxp/properties/maxParameterEntitySizeLimit
    //
    /////////////////////////////////////////////////////////////////////////////////////////
    
    @Test
    public void testEntitySizeLimit() throws Exception
    {
        doTestEntitySizeLimit(ParserType.SAX, EntityType.GENERAL);
        doTestEntitySizeLimit(ParserType.DOM, EntityType.GENERAL);
        doTestEntitySizeLimit(ParserType.SAX, EntityType.PARAMETER);
        doTestEntitySizeLimit(ParserType.DOM, EntityType.PARAMETER);
    }

    void doTestEntitySizeLimit(ParserType parserType, EntityType entityType) throws Exception
    {
//                                                          secure processing feature
//                                                          |        system property limit
//                                                          |        |   factory property limit
//                                                          |        |   |   security manager limit
//                                                          |        |   |   |  expected limit
        doTestEntitySizeLimitFails(parserType,  entityType, E.TRUE,  3,  5,  7, "7");
        doTestEntitySizeLimitPasses(parserType, entityType, E.TRUE,  3,  5,  0);
        doTestEntitySizeLimitFails(parserType,  entityType, E.TRUE,  3,  5, -1, "5");
        doTestEntitySizeLimitFails(parserType,  entityType, E.TRUE,  3,  0,  7, "7");
        doTestEntitySizeLimitPasses(parserType, entityType, E.TRUE,  3,  0,  0);
        doTestEntitySizeLimitPasses(parserType, entityType, E.TRUE,  3,  0, -1);
        doTestEntitySizeLimitFails(parserType,  entityType, E.TRUE,  3, -1,  7, "7");
        doTestEntitySizeLimitPasses(parserType, entityType, E.TRUE,  3, -1,  0);
        doTestEntitySizeLimitFails(parserType,  entityType, E.TRUE,  3, -1, -1, "3");

        doTestEntitySizeLimitFails(parserType,  entityType, E.TRUE,  0,  5,  7, "7");
        doTestEntitySizeLimitPasses(parserType, entityType, E.TRUE,  0,  5,  0);
        doTestEntitySizeLimitFails(parserType,  entityType, E.TRUE,  0,  5, -1, "5");
        doTestEntitySizeLimitFails(parserType,  entityType, E.TRUE,  0,  0,  7, "7");
        doTestEntitySizeLimitPasses(parserType, entityType, E.TRUE,  0,  0,  0);
        doTestEntitySizeLimitPasses(parserType, entityType, E.TRUE,  0,  0, -1);
        doTestEntitySizeLimitFails(parserType,  entityType, E.TRUE,  0, -1,  7, "7");
        doTestEntitySizeLimitPasses(parserType, entityType, E.TRUE,  0, -1,  0);
        doTestEntitySizeLimitPasses(parserType, entityType, E.TRUE,  0, -1, -1);

        doTestEntitySizeLimitFails(parserType,  entityType, E.TRUE, -1,  5,  7, "7");
        doTestEntitySizeLimitPasses(parserType, entityType, E.TRUE, -1,  5,  0);
        doTestEntitySizeLimitFails(parserType,  entityType, E.TRUE, -1,  5, -1, "5");
        doTestEntitySizeLimitFails(parserType,  entityType, E.TRUE, -1,  0,  7, "7");
        doTestEntitySizeLimitPasses(parserType, entityType, E.TRUE, -1,  0,  0);
        doTestEntitySizeLimitPasses(parserType, entityType, E.TRUE, -1,  0, -1);
        doTestEntitySizeLimitFails(parserType,  entityType, E.TRUE, -1, -1,  7, "7");
        doTestEntitySizeLimitPasses(parserType, entityType, E.TRUE, -1, -1,  0);
        doTestEntitySizeLimitPasses(parserType, entityType, E.TRUE, -1, -1, -1);

        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE,  3,  5,  7);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE,  3,  5,  0);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE,  3,  5, -1);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE,  3,  0,  7);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE,  3,  0,  0);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE,  3,  0, -1);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE,  3, -1,  7);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE,  3, -1,  0);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE,  3, -1, -1);

        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE,  0,  5,  7);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE,  0,  5,  0);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE,  0,  5, -1);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE,  0,  0,  7);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE,  0,  0,  0);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE,  0,  0, -1);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE,  0, -1,  7);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE,  0, -1,  0);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE,  0, -1, -1);

        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE, -1,  5,  7);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE, -1,  5,  0);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE, -1,  5, -1);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE, -1,  0,  7);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE, -1,  0,  0);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE, -1,  0, -1);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE, -1, -1,  7);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE, -1, -1,  0);
        doTestEntitySizeLimitPasses(parserType, entityType, E.FALSE, -1, -1, -1);

        doTestEntitySizeLimitFails(parserType,  entityType, E.DEFAULT,  3,  5,  7, "7");
        doTestEntitySizeLimitPasses(parserType, entityType, E.DEFAULT,  3,  5,  0);
        doTestEntitySizeLimitFails(parserType,  entityType, E.DEFAULT,  3,  5, -1, "5");
        doTestEntitySizeLimitFails(parserType,  entityType, E.DEFAULT,  3,  0,  7, "7");
        doTestEntitySizeLimitPasses(parserType, entityType, E.DEFAULT,  3,  0,  0);
        doTestEntitySizeLimitPasses(parserType, entityType, E.DEFAULT,  3,  0, -1);
        doTestEntitySizeLimitFails(parserType,  entityType, E.DEFAULT,  3, -1,  7, "7");
        doTestEntitySizeLimitPasses(parserType, entityType, E.DEFAULT,  3, -1,  0);
        doTestEntitySizeLimitFails(parserType,  entityType, E.DEFAULT,  3, -1, -1, "3");

        doTestEntitySizeLimitFails(parserType,  entityType, E.DEFAULT,  0,  5,  7, "7");
        doTestEntitySizeLimitPasses(parserType, entityType, E.DEFAULT,  0,  5,  0);
        doTestEntitySizeLimitFails(parserType,  entityType, E.DEFAULT,  0,  5, -1, "5");
        doTestEntitySizeLimitFails(parserType,  entityType, E.DEFAULT,  0,  0,  7, "7");
        doTestEntitySizeLimitPasses(parserType, entityType, E.DEFAULT,  0,  0,  0);
        doTestEntitySizeLimitPasses(parserType, entityType, E.DEFAULT,  0,  0, -1);
        doTestEntitySizeLimitFails(parserType,  entityType, E.DEFAULT,  0, -1,  7, "7");
        doTestEntitySizeLimitPasses(parserType, entityType, E.DEFAULT,  0, -1,  0);
        doTestEntitySizeLimitPasses(parserType, entityType, E.DEFAULT,  0, -1, -1);

        doTestEntitySizeLimitFails(parserType,  entityType, E.DEFAULT, -1,  5,  7, "7");
        doTestEntitySizeLimitPasses(parserType, entityType, E.DEFAULT, -1,  5,  0);
        doTestEntitySizeLimitFails(parserType,  entityType, E.DEFAULT, -1,  5, -1, "5");
        doTestEntitySizeLimitFails(parserType,  entityType, E.DEFAULT, -1,  0,  7, "7");
        doTestEntitySizeLimitPasses(parserType, entityType, E.DEFAULT, -1,  0,  0);
        doTestEntitySizeLimitPasses(parserType, entityType, E.DEFAULT, -1,  0, -1);
        doTestEntitySizeLimitFails(parserType,  entityType, E.DEFAULT, -1, -1,  7, "7");
        doTestEntitySizeLimitPasses(parserType, entityType, E.DEFAULT, -1, -1,  0);
        doTestEntitySizeLimitPasses(parserType, entityType, E.DEFAULT, -1, -1, -1);
    }

    void doTestEntitySizeLimitPasses(ParserType type, EntityType entityType, E secureProcessing, int systemLimit, int factoryLimit, int securityLimit)
    {
        try
        {
            doTestEntitySizeLimitParse(type, entityType, secureProcessing, systemLimit, factoryLimit, securityLimit); 
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Wasn't expecting exception: " + e);
        }
    }

    void doTestEntitySizeLimitFails(ParserType type, EntityType entityType, E secureProcessing, int systemLimit, int factoryLimit, int securityLimit, String expected) throws Exception
    {
        try
        {
            doTestEntitySizeLimitParse(type, entityType, secureProcessing, systemLimit, factoryLimit, securityLimit);
            fail("Expecting SAXParseException");
        }
        catch (SAXParseException e)
        {
            debug(e);
            String s = String.format("The parser has encountered more than \"%1$s\" bytes or characters within a %2$s entity; this is the limit imposed by the application.", expected, entityType.toString());
            debug(s);
            Assert.assertEquals(s, e.getMessage());
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Expecting SAXParseException");
        }
    }    

    void doTestEntitySizeLimitParse(ParserType parserType, EntityType entityType, E secureProcessing, int systemLimit, int factoryLimit, int securityLimit) throws Exception
    {
        try
        {
            if (systemLimit >= 0)
            {
                switch (entityType)
                {
                   case GENERAL:
                       System.setProperty(MAX_GENERAL_ENTITY_SIZE_LIMIT_PROPERTY_NAME, Integer.toString(systemLimit));
                       break;
                       
                   case PARAMETER:
                       System.setProperty(MAX_PARAMETER_ENTITY_SIZE_LIMIT_PROPERTY_NAME, Integer.toString(systemLimit));
                       break;
                       
                   default:
                       throw new Exception("Unrecognized entity type: " + entityType.toString());
                }
            }
            ParserFactory factory = ParserFactory.newInstance(parserType);
            factory.setFeature(NAMESPACES, namespaces());
            factory.setValidating(validating());
//            factory.setValidating(true);
//            factory.setNamespaceAware(true);
//            factory.setProperty("http://java.sun.com/xml/jaxp/properties/schemaLanguage", "http://www.w3.org/2001/XMLSchema");
            factory.setFeature(DISALLOW_DOCTYPE_DECL_FEATURE, false);
            if (factoryLimit >= 0)
            {
                switch (entityType)
                {
                   case GENERAL:
                       factory.setProperty(MAX_GENERAL_ENTITY_SIZE_LIMIT, factoryLimit);
                       break;
                       
                   case PARAMETER:
                       factory.setProperty(MAX_PARAMETER_ENTITY_SIZE_LIMIT, factoryLimit);
                       break;
                       
                   default:
                       throw new Exception("Unrecognized entity type: " + entityType.toString());
                }
            }
            if (!E.DEFAULT.equals(secureProcessing))
            {
                factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, secureProcessing.bool());
            }
            Parser parser = factory.newParser();
            if (securityLimit >= 0)
            {
                SecurityManager sm = (SecurityManager) parser.getProperty(SECURITY_MANAGER_PROPERTY);
                if (sm != null)
                {
                    switch (entityType)
                    {
                       case GENERAL:
                           sm.setGeneralEntitySizeLimit(securityLimit);
                           break;
                           
                       case PARAMETER:
                           sm.setParameterEntitySizeLimit(securityLimit);
                           break;
                           
                       default:
                           throw new Exception("Unrecognized entity type: " + entityType.toString());
                    }
                }
            }
            TestErrorHandler errorHandler = new TestErrorHandler();
            parser.setErrorHandler(errorHandler);
            
            ByteArrayInputStream baos = null;
            switch (entityType)
            {
               case GENERAL:
                   baos = new ByteArrayInputStream(getGeneralEntitySizeDoc().getBytes(Charset.forName("UTF-8")));
                   break;
                   
               case PARAMETER:
                   baos = new ByteArrayInputStream(getParameterEntitySizeDoc().getBytes(Charset.forName("UTF-8")));
                   break;
                   
               default:
                   throw new Exception("Unrecognized entity type: " + entityType.toString());
            }
            
      
            parser.parse(baos);
        }
        finally
        {
            if (systemLimit >= 0)
            {
                switch (entityType)
                {
                   case GENERAL:
                       System.setProperty(MAX_GENERAL_ENTITY_SIZE_LIMIT_PROPERTY_NAME, "");
                       break;
                       
                   case PARAMETER:
                       System.setProperty(MAX_PARAMETER_ENTITY_SIZE_LIMIT_PROPERTY_NAME, "");
                       break;
                       
                   default:
                       throw new Exception("Unrecognized entity type: " + entityType.toString());
                }
            }
        }
    }
    
    
    /////////////////////////////////////////////////////////////////////////////////////////
    //
    //  element depth limit
    //
    /////////////////////////////////////////////////////////////////////////////////////////
    
    @Test
    public void testElementDepthLimit() throws Exception
    {
        doTestElementDepthLimit(ParserType.SAX);
        doTestElementDepthLimit(ParserType.DOM);
    }

    void doTestElementDepthLimit(ParserType parserType) throws Exception
    {
        // Note. 
        
        // 1. The depth counting in xerces is such that the first element is given a depth of 2.
        // 2. The default value of maxElementDepth is Integer.MAX_VALUE, so the test will pass
        //    if neither element is set.
        // 3. The system property is set only if E.TRUE is passed. There's no need to test E.DEFAULT.
        
//                                                secure processing feature
//                                                |       system property limit
//                                                |       |   factory property limit
//                                                |       |   |   security manager limit
//                                                |       |   |   |  expected limit
        doTestElementDepthLimitFails(parserType,  E.TRUE, 2,  3,  5, 5);
        doTestElementDepthLimitPasses(parserType, E.TRUE, 2,  3,  0);
        doTestElementDepthLimitFails(parserType,  E.TRUE, 2,  3, -1, 3);
        doTestElementDepthLimitFails(parserType,  E.TRUE, 2,  0,  5, 5);
        doTestElementDepthLimitPasses(parserType, E.TRUE, 2,  0,  0);
        doTestElementDepthLimitPasses(parserType, E.TRUE, 2,  0, -1);
        doTestElementDepthLimitFails(parserType,  E.TRUE, 2, -1,  5, 5);
        doTestElementDepthLimitPasses(parserType, E.TRUE, 2, -1,  0);
        doTestElementDepthLimitFails(parserType,  E.TRUE, 2, -1, -1, 2);

        doTestElementDepthLimitFails(parserType,  E.TRUE, 0,  3,  5, 5);
        doTestElementDepthLimitPasses(parserType, E.TRUE, 0,  3,  0);
        doTestElementDepthLimitFails(parserType,  E.TRUE, 0,  3, -1, 3);
        doTestElementDepthLimitFails(parserType,  E.TRUE, 0,  0,  5, 5);
        doTestElementDepthLimitPasses(parserType, E.TRUE, 0,  0,  0);
        doTestElementDepthLimitPasses(parserType, E.TRUE, 0,  0, -1);
        doTestElementDepthLimitFails(parserType,  E.TRUE, 0, -1,  5, 5);
        doTestElementDepthLimitPasses(parserType, E.TRUE, 0, -1,  0);
        doTestElementDepthLimitPasses(parserType, E.TRUE, 0, -1, -1);

        doTestElementDepthLimitFails(parserType,  E.TRUE, -1,  3,  5, 5);
        doTestElementDepthLimitPasses(parserType, E.TRUE, -1,  3,  0);
        doTestElementDepthLimitFails(parserType,  E.TRUE, -1,  3, -1, 3);
        doTestElementDepthLimitFails(parserType,  E.TRUE, -1,  0,  5, 5);
        doTestElementDepthLimitPasses(parserType, E.TRUE, -1,  0,  0);
        doTestElementDepthLimitPasses(parserType, E.TRUE, -1,  0, -1);
        doTestElementDepthLimitFails(parserType,  E.TRUE, -1, -1,  5, 5);
        doTestElementDepthLimitPasses(parserType, E.TRUE, -1, -1,  0);
        doTestElementDepthLimitPasses(parserType, E.TRUE, -1, -1, -1);

        doTestElementDepthLimitPasses(parserType, E.FALSE, 2,  3,  5);
        doTestElementDepthLimitPasses(parserType, E.FALSE, 2,  3,  0);
        doTestElementDepthLimitPasses(parserType, E.FALSE, 2,  3, -1);
        doTestElementDepthLimitPasses(parserType, E.FALSE, 2,  0,  5);
        doTestElementDepthLimitPasses(parserType, E.FALSE, 2,  0,  0);
        doTestElementDepthLimitPasses(parserType, E.FALSE, 2,  0, -1);
        doTestElementDepthLimitPasses(parserType, E.FALSE, 2, -1,  5);
        doTestElementDepthLimitPasses(parserType, E.FALSE, 2, -1,  0);
        doTestElementDepthLimitPasses(parserType, E.FALSE, 2, -1, -1);

        doTestElementDepthLimitPasses(parserType, E.FALSE, 0,  3,  5);
        doTestElementDepthLimitPasses(parserType, E.FALSE, 0,  3,  0);
        doTestElementDepthLimitPasses(parserType, E.FALSE, 0,  3, -1);
        doTestElementDepthLimitPasses(parserType, E.FALSE, 0,  0,  5);
        doTestElementDepthLimitPasses(parserType, E.FALSE, 0,  0,  0);
        doTestElementDepthLimitPasses(parserType, E.FALSE, 0,  0, -1);
        doTestElementDepthLimitPasses(parserType, E.FALSE, 0, -1,  5);
        doTestElementDepthLimitPasses(parserType, E.FALSE, 0, -1,  0);
        doTestElementDepthLimitPasses(parserType, E.FALSE, 0, -1, -1);

        doTestElementDepthLimitPasses(parserType, E.FALSE, -1,  3,  5);
        doTestElementDepthLimitPasses(parserType, E.FALSE, -1,  3,  0);
        doTestElementDepthLimitPasses(parserType, E.FALSE, -1,  3, -1);
        doTestElementDepthLimitPasses(parserType, E.FALSE, -1,  0,  5);
        doTestElementDepthLimitPasses(parserType, E.FALSE, -1,  0,  0);
        doTestElementDepthLimitPasses(parserType, E.FALSE, -1,  0, -1);
        doTestElementDepthLimitPasses(parserType, E.FALSE, -1, -1,  5);
        doTestElementDepthLimitPasses(parserType, E.FALSE, -1, -1,  0);
        doTestElementDepthLimitPasses(parserType, E.FALSE, -1, -1, -1);
        
        doTestElementDepthLimitFails(parserType,  E.DEFAULT, 2,  3,  5, 5);
        doTestElementDepthLimitPasses(parserType, E.DEFAULT, 2,  3,  0);
        doTestElementDepthLimitFails(parserType,  E.DEFAULT, 2,  3, -1, 3);
        doTestElementDepthLimitFails(parserType,  E.DEFAULT, 2,  0,  5, 5);
        doTestElementDepthLimitPasses(parserType, E.DEFAULT, 2,  0,  0);
        doTestElementDepthLimitPasses(parserType, E.DEFAULT, 2,  0, -1);
        doTestElementDepthLimitFails(parserType,  E.DEFAULT, 2, -1,  5, 5);
        doTestElementDepthLimitPasses(parserType, E.DEFAULT, 2, -1,  0);
        doTestElementDepthLimitFails(parserType,  E.DEFAULT, 2, -1, -1, 2);

        doTestElementDepthLimitFails(parserType,  E.DEFAULT, 0,  3,  5, 5);
        doTestElementDepthLimitPasses(parserType, E.DEFAULT, 0,  3,  0);
        doTestElementDepthLimitFails(parserType,  E.DEFAULT, 0,  3, -1, 3);
        doTestElementDepthLimitFails(parserType,  E.DEFAULT, 0,  0,  5, 5);
        doTestElementDepthLimitPasses(parserType, E.DEFAULT, 0,  0,  0);
        doTestElementDepthLimitPasses(parserType, E.DEFAULT, 0,  0, -1);
        doTestElementDepthLimitFails(parserType,  E.DEFAULT, 0, -1,  5, 5);
        doTestElementDepthLimitPasses(parserType, E.DEFAULT, 0, -1,  0);
        doTestElementDepthLimitPasses(parserType, E.DEFAULT, 0, -1, -1);

        doTestElementDepthLimitFails(parserType,  E.DEFAULT, -1,  3,  5, 5);
        doTestElementDepthLimitPasses(parserType, E.DEFAULT, -1,  3,  0);
        doTestElementDepthLimitFails(parserType,  E.DEFAULT, -1,  3, -1, 3);
        doTestElementDepthLimitFails(parserType,  E.DEFAULT, -1,  0,  5, 5);
        doTestElementDepthLimitPasses(parserType, E.DEFAULT, -1,  0,  0);
        doTestElementDepthLimitPasses(parserType, E.DEFAULT, -1,  0, -1);
        doTestElementDepthLimitFails(parserType,  E.DEFAULT, -1, -1,  5, 5);
        doTestElementDepthLimitPasses(parserType, E.DEFAULT, -1, -1,  0);
        doTestElementDepthLimitPasses(parserType, E.DEFAULT, -1, -1, -1);
    }

    void doTestElementDepthLimitPasses(ParserType type, E secureProcessing, int systemLimit, int factoryLimit, int securityLimit)
    {
        try
        {
            doTestElementDepthLimitParse(type, secureProcessing, systemLimit, factoryLimit, securityLimit); 
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Wasn't expecting exception: " + e);
        }
    }

    void doTestElementDepthLimitFails(ParserType type, E secureProcessing, int systemLimit, int factoryLimit, int securityLimit, int expected) throws Exception
    {
        try
        {
            doTestElementDepthLimitParse(type, secureProcessing, systemLimit, factoryLimit, securityLimit);
            fail("Expecting SAXParseException");
        }
        catch (SAXParseException e)
        {
            debug(e);
//            e.printStackTrace();
            String s = String.format("The element \"ent%1$s\" has a depth of \"%2$s\" that exceeds the limit \"%3$s\" set by \"maxElementDepth\".", expected - 1, expected + 1, expected); 
            debug("s: " + s);
            Assert.assertEquals(s, e.getMessage());
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Expecting SAXParseException");
        }
    }    

    void doTestElementDepthLimitParse(ParserType parserType, E secureProcessing, int systemLimit, int factoryLimit, int securityLimit) throws Exception
    {
        try
        {
            if (systemLimit >= 0)
            {
                System.setProperty(MAX_ELEMENT_DEPTH_PROPERTY_NAME, Integer.toString(systemLimit));
            }
            ParserFactory factory = ParserFactory.newInstance(parserType);
            if (!E.DEFAULT.equals(secureProcessing))
            {
                factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, secureProcessing.bool());
            }
            if (factoryLimit >=0)
            {
                factory.setProperty(getMaxElementDepthProperty(), factoryLimit);
            }
            Parser parser = factory.newParser();
            factory.setFeature(NAMESPACES, namespaces());
            factory.setValidating(validating());
            if (securityLimit >= 0)
            {
                SecurityManager sm = (SecurityManager) parser.getProperty(SECURITY_MANAGER_PROPERTY);
                if (sm != null)
                {
                    sm.setMaxElementDepth(securityLimit);
                }
            }
            TestErrorHandler errorHandler = new TestErrorHandler();
            parser.setErrorHandler(errorHandler);
            ByteArrayInputStream baos = new ByteArrayInputStream(getMaxElementDepthDoc().getBytes(Charset.forName("UTF-8")));
            parser.parse(baos);
        }
        finally
        {
            if (systemLimit >= 0)
            {
                System.setProperty(MAX_ELEMENT_DEPTH_PROPERTY_NAME, "");
            }
        }
    }
    
    
    /////////////////////////////////////////////////////////////////////////////////
    //
    //     Classes
    //
    /////////////////////////////////////////////////////////////////////////////////
    static class TestHandler extends DefaultHandler
    {
        public int count;
        public StringBuffer sb = new StringBuffer();

        public void startElement (String uri, String localName, String qName, Attributes attributes) throws SAXException
        {
            count++;
            super.startElement(uri, localName, qName, attributes);
        }
        public void characters (char ch[], int start, int length) throws SAXException
        {
            sb.append(ch, start, length);
        }
        public String getText()
        {
            return sb.toString();
        }
        
        public void error (SAXParseException e) throws SAXException
        {
            throw e;
        }
    }
    
    static class TestErrorHandler implements ErrorHandler
    {
        public Exception e;
        
        public void warning(SAXParseException paramSAXParseException) throws SAXException
        {
//            paramSAXParseException.printStackTrace();
            e = paramSAXParseException;
        }

        public void error(SAXParseException paramSAXParseException) throws SAXException
        {
//            paramSAXParseException.printStackTrace();
            e = paramSAXParseException;
            throw paramSAXParseException;
        }

        public void fatalError(SAXParseException paramSAXParseException) throws SAXException
        {
//            paramSAXParseException.printStackTrace();
            e = paramSAXParseException;
            throw paramSAXParseException;
        }
    }
    
    static abstract class ParserFactory
    {
        static ParserFactory newInstance(ParserType type) throws Exception
        {
            switch (type)
            {
               case DOM:
                   return new TestDOMParserFactory();
                   
               case SAX:
                   return new TestSAXParserFactory();
                   
               default:
                   throw new Exception("Unrecognized parser type: " + type.toString());
            }
        }
        
        abstract public Parser newParser() throws Exception;
        abstract public void setFeatures(Map<String, Boolean> features) throws Exception;
        abstract public void setFeature(String name, boolean value) throws Exception;
        abstract public void setProperty(String name, Object value) throws Exception;
        abstract public void setValidating(boolean b) throws Exception;
        abstract public void setNamespaceAware(boolean b) throws Exception;
    }
    
    static class TestSAXParserFactory extends ParserFactory
    {
        private SAXParserFactory spf = SAXParserFactory.newInstance();
        private HashMap<String, Object> properties = new HashMap<String, Object>();

        @Override
        public Parser newParser() throws Exception
        {
            SAXParserImpl parser = new SAXParserImpl(spf.newSAXParser());
            for (Iterator<String> it = properties.keySet().iterator(); it.hasNext(); )
            {
                String key = it.next();
                parser.setProperty(key, properties.get(key));
            }
            return parser;
        }
        
        @Override
        public void setFeatures(Map<String, Boolean> features) throws Exception
        {
            for (Iterator<String> it = features.keySet().iterator(); it.hasNext(); )
            {
                String key = it.next();
                spf.setFeature(key, features.get(key));
            }  
        }
        
        @Override
        public void setFeature(String name, boolean value) throws Exception
        {
            spf.setFeature(name, value);
        }
        
        @Override
        public void setProperty(String name, Object value) throws Exception
        {
            properties.put(name, value);
        }
        
        @Override
        public void setValidating(boolean b) throws Exception
        {
            spf.setValidating(b);
        }

        @Override
        public void setNamespaceAware(boolean b) throws Exception
        {
            spf.setNamespaceAware(b);
        }
    }
    
    static class TestDOMParserFactory extends ParserFactory
    {
        private  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        @Override
        public Parser newParser() throws Exception
        {
            DocumentBuilderImpl db = (DocumentBuilderImpl) dbf.newDocumentBuilder();
            return new DOMParserImpl(db);
        }
        
        @Override
        public void setFeatures(Map<String, Boolean> features) throws Exception
        {
            for (Iterator<String> it = features.keySet().iterator(); it.hasNext(); )
            {
                String key = it.next();
                dbf.setFeature(key, features.get(key));
            }
        }
        
        @Override
        public void setFeature(String name, boolean value) throws Exception
        {
            dbf.setFeature(name, value);
        }
        
        @Override
        public void setProperty(String name, Object value) throws Exception
        {
            dbf.setAttribute(name, value);
        }
        
        @Override
        public void setValidating(boolean b) throws Exception
        {
            dbf.setValidating(b);
        }
        
        @Override
        public void setNamespaceAware(boolean b) throws Exception
        {
            dbf.setNamespaceAware(b);
        }
    }
    
    interface Parser
    {
        void parse(InputStream is) throws Exception;
        void parse(InputSource is) throws Exception;
        void setProperty(String name, Object value) throws Exception;
        Object getProperty(String name) throws Exception;
        void setErrorHandler(ErrorHandler errorHandler) throws Exception;
        String getText() throws Exception;
    }
    
    static class SAXParserImpl implements Parser
    {
        private SAXParser parser;
        private TestHandler handler = new TestHandler();
        private TestErrorHandler errorHandler = new TestErrorHandler();
        
        public SAXParserImpl(SAXParser parser) throws Exception
        {
            this.parser = parser;
            this.parser.getXMLReader().setErrorHandler(errorHandler);
        }

        public void parse(InputStream is) throws Exception
        {
            parser.parse(is, handler);
        }
        
        public void parse(InputSource is) throws Exception
        {
            parser.parse(is, handler);
        }

        public void setProperty(String name, Object value) throws Exception
        {
            parser.getXMLReader().setProperty(name, value);
        }
        
        public Object getProperty(String name) throws Exception
        {
            return parser.getProperty(name);
        }

        public void setErrorHandler(ErrorHandler errorHandler) throws Exception
        {
            parser.getXMLReader().setErrorHandler(errorHandler);
        }
        
        public String getText() throws Exception
        {
            return handler.getText();
        }
    }
    
    static class DOMParserImpl implements Parser
    {
        private DocumentBuilderImpl builder;
        private TestErrorHandler errorHandler = new TestErrorHandler();
        private Document document;
        
        public DOMParserImpl(DocumentBuilderImpl builder)
        {
            this.builder = builder;
            this.builder.setErrorHandler(errorHandler);
        }

        public void parse(InputStream is) throws Exception
        {
            document = builder.parse(new InputSource(is));
        }
        
        public void parse(InputSource is) throws Exception
        {
            document = builder.parse(is);
        }
        
        public void setProperty(String name, Object value) throws Exception
        {
            builder.getDOMParser().setProperty(name, value);
        }
        
        public Object getProperty(String name) throws Exception
        {
            return builder.getDOMParser().getProperty(name);
        }

        public void setErrorHandler(ErrorHandler errorHandler) throws Exception
        {
            builder.setErrorHandler(errorHandler);
        }
        
        public String getText() throws Exception
        {
            StringBuffer sb = new StringBuffer();
            doGetText(sb, document.getChildNodes());
            return sb.toString();
        }
        
        void doGetText(StringBuffer sb, NodeList list)
        {
          for (int i = 0; i < list.getLength(); i++)
          {
              if (Node.TEXT_NODE == list.item(i).getNodeType())
              {
                  sb.append(list.item(i).getNodeValue());
                  return;
              }
              doGetText(sb, list.item(i).getChildNodes());
          }
        }
    }
}
