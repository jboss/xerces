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
import junit.framework.Assert;

import org.xml.sax.SAXParseException;

/**
 * 
 * namespaces:  true
 * validating:  false
 * xml version: 1.0
 * 
 * @author <a href="mailto:ron.sigal@jboss.com">Ron Sigal</a>
 * @date October 30, 2015
 *
 */
public class TestSecureProcessingNS extends TestSecureProcessing
{
    protected boolean namespaces()
    {
        return true;
    }
    
    protected String getExternalGeneralEntityDoc()
    {
        String externalGeneralEntityDoc = 
                "<!DOCTYPE test:externalGeneralEntity " +
                "[<!ENTITY externalGeneralEntity SYSTEM \"file://" + currentDirectory + "/src/test/java/org/apache/xerces/test/secureprocessing/external.text\">" +
                " <!ELEMENT test:externalGeneralEntity ANY>" +
                " <!ATTLIST test:externalGeneralEntity xmlns:test CDATA #REQUIRED>" +
                "]>" +
                "<test:externalGeneralEntity xmlns:test=\"http://www.jboss.com/secureProcessing\">&externalGeneralEntity;</test:externalGeneralEntity>";
        return externalGeneralEntityDoc;
    }

    protected String getExternalParameterEntityDoc()
    {
        String externalParameterEntityDoc = 
                "<!DOCTYPE test:externalParameterEntity " +
                "[<!ENTITY % externalParameterEntity SYSTEM \"file://" + currentDirectory + "/src/test/java/org/apache/xerces/test/secureprocessing/externalParameterEntityNS.dtd\">" + 
                " %externalParameterEntity;" + 
                "]>" +
                "<test:externalParameterEntity xmlns:test=\"http://www.jboss.com/secureProcessing\">&foo;</test:externalParameterEntity>";
        return externalParameterEntityDoc;
    }
    
    protected String getInternalDTDDoc()
    {
        String internalDTDDoc =
                XMLVersion() +
                "<!DOCTYPE test:internalDTDDoc " +
                "[<!ENTITY foo '0123456789'>" +
                " <!ELEMENT test:internalDTDDoc ANY>" +
                " <!ATTLIST test:internalDTDDoc xmlns:test CDATA #REQUIRED>" +
                "]>" +
                "<test:internalDTDDoc xmlns:test=\"http://www.jboss.com/secureProcessing\">&foo;</test:internalDTDDoc>";
        return internalDTDDoc;
    }
    
    protected String getBigElementDoctype()
    {
        String bigElementDoctype =
                XMLVersion() +
                "<!DOCTYPE test:tag [" +
                      "<!ENTITY foo 'foo'>" +
                      "<!ENTITY foo1 '&foo;&foo;&foo;&foo;&foo;&foo;&foo;&foo;&foo;&foo;'>" +
                      "<!ENTITY foo2 '&foo1;&foo1;&foo1;&foo1;&foo1;&foo1;&foo1;&foo1;&foo1;&foo1;'>" +
                      "<!ENTITY foo3 '&foo2;&foo2;&foo2;&foo2;&foo2;&foo2;&foo2;&foo2;&foo2;&foo2;'>" +
                      "<!ENTITY foo4 '&foo3;&foo3;&foo3;&foo3;&foo3;&foo3;&foo3;&foo3;&foo3;&foo3;'>" +
                      "<!ENTITY foo5 '&foo4;&foo4;&foo4;&foo4;&foo4;&foo4;&foo4;&foo4;&foo4;&foo4;'>" +
                      "<!ENTITY foo6 '&foo5;&foo5;&foo5;&foo5;&foo5;&foo5;&foo5;&foo5;&foo5;&foo5;'>" +
                      "<!ELEMENT test:tag (subtag)>" +
                      "<!ATTLIST test:tag xmlns:test CDATA #REQUIRED>" +
                      "<!ELEMENT subtag (#PCDATA)>" +
                      "]>";
        String body = "<test:tag xmlns:test=\"http://www.jboss.com/secureProcessing\"><subtag>&foo5;</subtag></test:tag>";
        String bigXmlRootElement = bigElementDoctype + body;
        return bigXmlRootElement;
    }
    
    @Override
    protected String getBigAttributeDoc()
    {
        if (bigAttributeDoc == null)
        {
            StringBuffer sb = new StringBuffer();
            sb.append("<test:bar xmlns:test=\"http://www.jboss.com/secureProcessing\" ");
            for (int i = 0; i < 100; i++)
            {
                sb.append("attr" + i + "=\"x\" ");  
            }
            sb.append("/>");
            bigAttributeDoc = sb.toString();
        }
        return bigAttributeDoc;
    }
    
    @Override
    protected String getReallyBigAttributeDoc()
    {
        if (reallyBigAttributeDoc == null)
        {
            StringBuffer sb = new StringBuffer();
            sb.append("<test:bar xmlns:test=\"http://www.jboss.com/secureProcessing\" ");
            for (int i = 0; i < 12000; i++)
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
        String file = System.getProperty("user.dir") + "/src/test/java/org/apache/xerces/test/secureprocessing/test_ns.xsd";
        StringBuffer sb = new StringBuffer();
        sb.append(XMLVersion());
        sb.append("<test:foo xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'");
        sb.append("          xmlns:test=\"http://www.jboss.com/secureProcessing\"");
        sb.append("          xsi:schemaLocation=\"http://www.jboss.com/secureProcessing " + file + "\">");
        for (int i = 0; i < 9999; i++)
        {
           sb.append("<test:bar>x</test:bar>");  
        }
        sb.append("</test:foo>");
        String maxOccursDoc = sb.toString();
        return maxOccursDoc;
    }
    
    protected String getExternalDTDWithInternalDTDDoc()
    {
        String externalDTDWithInternalDTDDoc = 
                XMLVersion() +
                "<!DOCTYPE test:foo SYSTEM \"file://" + currentDirectory + "/src/test/java/org/apache/xerces/test/secureprocessing/external_ns.dtd\"[" + 
                "]>" +
                "<test:foo xmlns:test=\"http://www.jboss.com/secureProcessing\">&foo;</test:foo>";
        return externalDTDWithInternalDTDDoc;
    }

    protected String getExternalDTDWithoutInternalDTDDoc()
    {
        String externalDTDWithoutInternalDTDDoc = 
                XMLVersion() +
                "<!DOCTYPE test:foo SYSTEM \"file://" + currentDirectory + "/src/test/java/org/apache/xerces/test/secureprocessing/external_ns.dtd\"" + 
                ">" +
                "<test:foo xmlns:test=\"http://www.jboss.com/secureProcessing\">&foo;</test:foo>";
        return externalDTDWithoutInternalDTDDoc;
    }
    
    protected String getExternalSchemaDoc()
    {
        String file = System.getProperty("user.dir") + "/src/test/java/org/apache/xerces/test/secureprocessing/foo_ns.xsd";
        StringBuffer sb = new StringBuffer();
        sb.append(XMLVersion());
        sb.append("<test:foo xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'");
        sb.append("     xmlns:test=\"http://www.jboss.com/secureProcessing\"");
        sb.append("     xsi:schemaLocation=\"http://www.jboss.com/secureProcessing " + file + "\">");
        sb.append("<bar>x</bar>");  
        sb.append("</test:foo>");
        String externalSchemaDoc = sb.toString();
        debug(externalSchemaDoc);
        return externalSchemaDoc;
    }

    protected String getTotalEntitySizeDoc()
    {
        String file = System.getProperty("user.dir") + "/tests/secure/sax/test_ns.xsd";
        String totalEntitySizeDoc =
                XMLVersion() +
                "<!DOCTYPE test:totalEntitySizeDoc ["
                + "<!ENTITY foo1 '13'>"
                + "<!ENTITY foo2 '35'>"
                + "<!ENTITY foo3 '57'>"
                + "<!ENTITY foo4 '79'>"
                + "<!ELEMENT test:totalEntitySizeDoc EMPTY>"
                + "<!ATTLIST test:totalEntitySizeDoc "
                + "              xmlns:test CDATA #REQUIRED "
                + "              xmlns:xsi  CDATA #REQUIRED "
                + "              xsi:schemaLocation CDATA #REQUIRED>"
                + "]>"
                + "<test:totalEntitySizeDoc xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'"
                + "     xmlns:test=\"http://www.jboss.com/secureProcessing\""
                + "     xsi:schemaLocation=\"http://www.jboss.com/secureProcessing " + file + "\"/>";
        return totalEntitySizeDoc;
    }
    
    protected String getGeneralEntitySizeDoc()
    {
        String file = System.getProperty("user.dir") + "/src/test/java/org/apache/xerces/test/secureprocessing/test_ns.xsd";
        String generalEntitySizeDoc = 
                XMLVersion() +
                "<!DOCTYPE test:generalEntitySizeDoc ["
                + "<!ENTITY foo '12345678'>"
                + "<!ELEMENT test:generalEntitySizeDoc EMPTY>"
                + "<!ATTLIST test:generalEntitySizeDoc "
                + "              xmlns:test CDATA #REQUIRED "
                + "              xmlns:xsi  CDATA #REQUIRED "
                + "              xsi:schemaLocation CDATA #REQUIRED>"
                + "]>"
                + "<test:generalEntitySizeDoc xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'"
                + "     xmlns:test=\"http://www.jboss.com/secureProcessing\""
                + "     xsi:schemaLocation=\"http://www.jboss.com/secureProcessing " + file + "\"/>";
        return generalEntitySizeDoc;
    }
    
    protected String getParameterEntitySizeDoc()
    {
        String file = System.getProperty("user.dir") + "/src/test/java/org/apache/xerces/test/secureprocessing/test_ns.xsd";
        String parameterEntitySizeDoc = 
                XMLVersion() +
                "<!DOCTYPE test:parameterEntitySizeDoc ["
                + "<!ENTITY % foo '12345678'>"
                + "<!ELEMENT test:parameterEntitySizeDoc EMPTY>"
                + "<!ATTLIST test:parameterEntitySizeDoc "
                + "              xmlns:test CDATA #REQUIRED "
                + "              xmlns:xsi  CDATA #REQUIRED "
                + "              xsi:schemaLocation CDATA #REQUIRED>"
                + "]>"
                + "<test:parameterEntitySizeDoc xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'"
                + "     xmlns:test=\"http://www.jboss.com/secureProcessing\""
                + "     xsi:schemaLocation=\"http://www.jboss.com/secureProcessing " + file + "\"/>";
        return parameterEntitySizeDoc;
    }
    
    protected String getMaxElementDepthDoc()
    {
        String file = System.getProperty("user.dir") + "/src/test/java/org/apache/xerces/test/secureprocessing/ent_ns.xsd";
        String maxElementDepthDoc = 
                XMLVersion()
                + "<test:ent0 xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'"
                + "     xmlns:test=\"http://www.jboss.com/secureProcessing\""
                + "     xsi:schemaLocation=\"http://www.jboss.com/secureProcessing " + file + "\">"
                +    "<ent1>\r" +
                        "<ent2>\r" +
                           "<ent3>\r" +
                              "<ent4>\r" +
                              "</ent4>\r" +
                           "</ent3>\r" +
                        "</ent2>\r" +
                     "</ent1>\r" +
                  "</test:ent0>";
        return maxElementDepthDoc;
    }    
    
    
    /**
     * We override doTestsExternalSchemaFails() because of the behavior of org.apache.xerces.impl.xs.XMLSchemaValidator.storeLocations().
     * storeLocations() looks for the attributes schemaLocation and noNamespaceSchemaLocation to find the document's
     * grammar, but it behaves differently according to whether or not the grammar has a namespace.
     * 
     * 1. If the grammar has a namespace, storeLocations() looks at the value of the accessExternalSchema property. If
     *    the schema is accessed by a protocol which is ruled out by accessExternalSchema, then the address of the
     *    grammar is not stored. Consequently, an exception is thrown by org.apache.xerces.impl.xs.XMLSchemaValidator.handleStartElement()
     *    indicating that the grammar cannot be found.
     *    
     * 2. If the grammar does not have a namespace, storeLocations() stores the address of the grammar, regardless of the
     *    value of accessExternalSchema. If the protocol is prohibited, an exception is thrown later by
     *    org.apache.xerces.impl.xs.XMLSchemaLoader.loadSchema() indicating that the problem is due to the value
     *    of the accessExternalSchema property.
     */
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
            Assert.assertTrue(e.getMessage().contains("cvc-elt.1.a: Cannot find the declaration of element 'test:foo'."));
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Expecting SAXParseException, not " + e);
        }
    }
}
