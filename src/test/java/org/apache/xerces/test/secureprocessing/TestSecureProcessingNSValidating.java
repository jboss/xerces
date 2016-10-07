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
 * validating:  true
 * xml version: 1.0
 * 
 * @author <a href="mailto:ron.sigal@jboss.com">Ron Sigal</a>
 * @date December 16, 2015
 * 
 */
public class TestSecureProcessingNSValidating extends TestSecureProcessingNS
{
    @Override
    protected boolean validating()
    {
        return true;
    }

    @Override
    protected String getBigAttributeDoc()
    {
        if (bigAttributeDoc == null)
        {
            StringBuffer sb = new StringBuffer();
            sb.append(XMLVersion());
            sb.append("<!DOCTYPE bar [");
            sb.append("  <!ELEMENT bar EMPTY>");
            sb.append("  <!ATTLIST bar ");
            for (int i = 0; i < 100; i++)
            {
                sb.append("attr" + i + " CDATA #REQUIRED ");
            }
            sb.append(">]>");
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
    
    @Override
    protected String getReallyBigAttributeDoc()
    {
        if (reallyBigAttributeDoc == null)
        {
            StringBuffer sb = new StringBuffer();
            sb.append(XMLVersion());
            sb.append("<!DOCTYPE bar [");
            sb.append("  <!ELEMENT bar EMPTY>");
            sb.append("  <!ATTLIST bar ");
            for (int i = 0; i < 10002; i++)
            {
                sb.append("attr" + i + " CDATA #REQUIRED ");
            }
            sb.append(">]>");
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
    
    @Override
    void doTestExternalEntities(ParserType type, EntityType entityType, E systemProperty, E secureProcessing, E externalParameterEntities, String expected) throws Exception
    {
        if (entityType.equals(EntityType.GENERAL) || !"".equals(expected))
        {
            super.doTestExternalEntities(type, entityType, systemProperty, secureProcessing, externalParameterEntities, expected);
            return;
        }
        else
        {
            try
            {
                String result = doTestExternalEntitiesParse(type, entityType, systemProperty, secureProcessing, externalParameterEntities);
                debug("doTestExternalParameterEntitiesPasses(): " + result);
                Assert.fail("Expected SAXParseException");
            }
            catch (SAXParseException e)
            {
                debug(e.getLocalizedMessage());
                Assert.assertTrue(e.getLocalizedMessage().indexOf("Element type \"test:externalParameterEntity\" must be declared.") > -1);
            }
            catch (Exception e)
            {
                e.printStackTrace();
                fail("Expecting SAXParseException, not " + e);
            }
        }
        return;
    }
    
    @Override
    void doTestExternalDTD(ParserType type, E systemProperty, E secureProcessing, E loadExternalDTD, String systemProtocols, String factoryProtocols, String securityManagerProtocols, String expected) throws Exception
    {
        if (!"".equals(expected))
        {
            super.doTestExternalDTD(type, systemProperty, secureProcessing, loadExternalDTD, systemProtocols, factoryProtocols, securityManagerProtocols, expected);
            return;
        }
        
        try
        {
            String text = doTestExternalDTDParse(type, systemProperty, secureProcessing, loadExternalDTD, systemProtocols, factoryProtocols, securityManagerProtocols, getExternalDTDWithInternalDTDDoc());
            debug("text: " + text);
            Assert.assertEquals(expected, text);
        }
        catch (SAXParseException e)
        {
            Assert.assertTrue(e.getLocalizedMessage().indexOf("Element type \"test:foo\" must be declared.") > -1);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Expecting SAXParseException, not " + e);
        }
        
        try
        {
            String text = doTestExternalDTDParse(type, systemProperty, secureProcessing, loadExternalDTD, systemProtocols, factoryProtocols, securityManagerProtocols, getExternalDTDWithoutInternalDTDDoc());
            debug("text: " + text);
            Assert.assertEquals(expected, text);
        }
        catch (SAXParseException e)
        {
            Assert.assertTrue(e.getLocalizedMessage().indexOf("Element type \"test:foo\" must be declared.") > -1);
        }
        catch (Exception e)
        {
            fail("Expecting SAXParseException, not " + e);
        } 
    }
}
