/*
 * The Apache Software License, Version 1.1
 *
 *
 * Copyright (c) 1999,2000 The Apache Software Foundation.  All rights 
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:  
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Xerces" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written 
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation and was
 * originally based on software copyright (c) 1999, International
 * Business Machines, Inc., http://www.apache.org.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 */

package org.apache.xerces.impl.validation.grammars;

import org.apache.xerces.xni.XMLString;
import org.apache.xerces.xni.XMLDTDContentModelHandler;
import org.apache.xerces.xni.XMLDTDHandler;
import org.apache.xerces.impl.validation.Grammar;
import org.apache.xerces.impl.validation.ContentModelValidator;
import org.apache.xerces.impl.validation.XMLElementDecl;
import org.apache.xerces.impl.validation.XMLAttributeDecl;
import org.apache.xerces.impl.validation.XMLNotationDecl;
import org.apache.xerces.impl.validation.XMLEntityDecl;
import org.apache.xerces.impl.validation.XMLSimpleType;
import org.apache.xerces.impl.validation.datatypes.DatatypeValidatorFactoryImpl;
import org.apache.xerces.xni.QName;
import org.xml.sax.SAXException;

/**
 * @author Stubs generated by DesignDoc on Mon Sep 11 11:10:57 PDT 2000
 * @version $Id$
 */
public class DTDGrammar
extends Grammar
implements XMLDTDHandler, XMLDTDContentModelHandler {

    //
    // Data
    //

    /** Current ElementIndex */
    private int              fCurrentElementIndex;

    /** Element declaration. */
    private XMLElementDecl    fElementDecl        = new XMLElementDecl();

    /** Current AttributeIndex */
    private int               fCurrentAttributeIndex;

    /** Attribute declaration. */
    private XMLAttributeDecl  fAttributeDecl      = new XMLAttributeDecl();

    /** QName holder           */
    private QName             fQName              = new QName();

    /** XMLEntityDecl. */
    private XMLEntityDecl     fEntityDecl         = new XMLEntityDecl();

    /** internal XMLEntityDecl. */
    private XMLEntityDecl     fInternalEntityDecl = new XMLEntityDecl();

    /** external XMLEntityDecl */
    private XMLEntityDecl     fExternalEntityDecl = new XMLEntityDecl();

    /** Simple Type. */
    private XMLSimpleType     fSimpleType         = new XMLSimpleType();

    /** ContentValidator.  */
    private ContentModelValidator fContentModelValidator;


    // debugging

    /** Debug DTDGrammar. */
    private static final boolean DEBUG_SCANNER_STATE = false;

    //
    // Constructors
    //

    /** Default constructor. */
    public DTDGrammar() {
        this( "" );
    }

    /**
     * 
     * 
     * @param targetNamespace 
     */
    public DTDGrammar(String targetNamespace) {
        setTargetNameSpace( targetNamespace );
    }

    //
    // XMLDTDHandler methods
    //

    /**
     * This method notifies of the start of an entity. The DTD has the 
     * pseudo-name of "[dtd]; and parameter entity names start with '%'.
     * <p>
     * <strong>Note:</strong> Since the DTD is an entity, the handler
     * will be notified of the start of the DTD entity by calling the
     * startEntity method with the entity name "[dtd]" <em>before</em> calling
     * the startDTD method.
     * 
     * @param name     The name of the entity.
     * @param publicId The public identifier of the entity if the entity
     *                 is external, null otherwise.
     * @param systemId The system identifier of the entity if the entity
     *                 is external, null otherwise.
     * @param encoding The auto-detected IANA encoding name of the entity
     *                 stream. This value will be null in those situations
     *                 where the entity encoding is not auto-detected (e.g.
     *                 internal parameter entities).
     *
     * @throws SAXException Thrown by handler to signal an error.
     */
    public void startEntity(String name, String publicId, String systemId, 
                            String encoding) throws SAXException {
        this.fEntityDecl.setValues( name, publicId, systemId, null, null, false );//fill internal fEntityDecl struct
    }

    /**
     * Notifies of the presence of a TextDecl line in an entity. If present,
     * this method will be called immediately following the startEntity call.
     * <p>
     * <strong>Note:</strong> This method is only called for external
     * parameter entities referenced in the DTD.
     * 
     * @param version  The XML version, or null if not specified.
     * @param encoding The IANA encoding name of the entity.
     *
     * @throws SAXException Thrown by handler to signal an error.
     */
    public void textDecl(String version, String encoding) throws SAXException {
    }

    /**
     * The start of the DTD.
     *
     * @throws SAXException Thrown by handler to signal an error.
     */
    public void startDTD() throws SAXException {
    } // startDTD

    /**
     * A comment.
     * 
     * @param text The text in the comment.
     *
     * @throws SAXException Thrown by application to signal an error.
     */
    public void comment(XMLString text) throws SAXException {
    } // comment

    /**
     * A processing instruction. Processing instructions consist of a
     * target name and, optionally, text data. The data is only meaningful
     * to the application.
     * <p>
     * Typically, a processing instruction's data will contain a series
     * of pseudo-attributes. These pseudo-attributes follow the form of
     * element attributes but are <strong>not</strong> parsed or presented
     * to the application as anything other than text. The application is
     * responsible for parsing the data.
     * 
     * @param target The target.
     * @param data   The data or null if none specified.
     *
     * @throws SAXException Thrown by handler to signal an error.
     */
    public void processingInstruction(String target, XMLString data)
    throws SAXException {
    } // processingInstruction

    /**
     * The start of the external subset.
     *
     * @throws SAXException Thrown by handler to signal an error.
     */
    public void startExternalSubset() throws SAXException {
    } // startExternalSubset

    /**
     * The end of the external subset.
     *
     * @throws SAXException Thrown by handler to signal an error.
     */
    public void endExternalSubset() throws SAXException {
    } // endExternalSubset

    /**
     * An element declaration.
     * 
     * @param name         The name of the element.
     * @param contentModel The element content model.
     *
     * @throws SAXException Thrown by handler to signal an error.
     */
    public void elementDecl(String name, String contentModel)
    throws SAXException {
        fCurrentElementIndex = createElementDecl();//create element decl
        
        System.out.println(  "name = " + fElementDecl.name.localpart );
        System.out.println(  "Type = " + fElementDecl.type );
        
        setElementDecl(fCurrentElementIndex, fElementDecl );//set internal structure
    } // elementDecl

    /**
     * The start of an attribute list.
     * 
     * @param elementName The name of the element that this attribute
     *                    list is associated with.
     *
     * @throws SAXException Thrown by handler to signal an error.
     */
    public void startAttlist(String elementName) throws SAXException {
    } // startAttlist

    /**
     * An attribute declaration.
     * 
     * @param elementName   The name of the element that this attribute
     *                      is associated with.
     * @param attributeName The name of the attribute.
     * @param type          The attribute type. This value will be one of
     *                      the following: "CDATA", "ENTITY", "ENTITIES",
     *                      "ENUMERATION", "ID", "IDREF", "IDREFS", 
     *                      "NMTOKEN", "NMTOKENS", or "NOTATION".
     * @param enumeration   If the type has the value "ENUMERATION", this
     *                      array holds the allowed attribute values;
     *                      otherwise, this array is null.
     * @param defaultType   The attribute default type. This value will be
     *                      one of the following: "#FIXED", "#IMPLIED",
     *                      "#REQUIRED", or null.
     * @param defaultValue  The attribute default value, or null if no
     *                      default value is specified.
     *
     * @throws SAXException Thrown by handler to signal an error.
     */
    public void attributeDecl(String elementName, String attributeName, String type, String[] enumeration, String defaultType, XMLString defaultValue)
    throws SAXException {

        fCurrentAttributeIndex = createAttributeDecl();// Create current Attribute Decl

        fSimpleType.clear();
        if ( defaultType != null ) {
            if ( defaultType.equals( "FIXED") ) {
                fSimpleType.defaultType = fSimpleType.DEFAULT_TYPE_FIXED;
            } else if ( defaultType.equals( "IMPLIED") ) {
                fSimpleType.defaultType = fSimpleType.DEFAULT_TYPE_IMPLIED;
            } else if ( defaultType.equals( "REQUIRED") ) {
                fSimpleType.defaultType = fSimpleType.DEFAULT_TYPE_REQUIRED;
            }
        }
        fSimpleType.defaultValue      = defaultValue.toString();
        fSimpleType.enumeration       = enumeration;
        fSimpleType.datatypeValidator = DatatypeValidatorFactoryImpl.getDatatypeRegistry().getDatatypeValidator(type);

        fQName.clear();
        fQName.setValues(null, null, attributeName, null);


        fAttributeDecl.clear();
        fAttributeDecl.simpleType     = fSimpleType;
        fAttributeDecl.setValues( fQName, fSimpleType, false );

        setAttributeDecl( fCurrentElementIndex, fCurrentAttributeIndex,
                          fAttributeDecl );

    } // attributeDecl

    /**
     * The end of an attribute list.
     *
     * @throws SAXException Thrown by handler to signal an error.
     */
    public void endAttlist() throws SAXException {
    } // endAttlist

    /**
     * An internal entity declaration.
     * 
     * @param name The name of the entity. Parameter entity names start with
     *             '%', whereas the name of a general entity is just the 
     *             entity name.
     * @param text The value of the entity.
     *
     * @throws SAXException Thrown by handler to signal an error.
     */
    public void internalEntityDecl(String name, XMLString text)
    throws SAXException {
    } // internalEntityDecl

    /**
     * An external entity declaration.
     * 
     * @param name     The name of the entity. Parameter entity names start
     *                 with '%', whereas the name of a general entity is just
     *                 the entity name.
     * @param publicId The public identifier of the entity or null if the
     *                 the entity was specified with SYSTEM.
     * @param systemId The system identifier of the entity.
     *
     * @throws SAXException Thrown by handler to signal an error.
     */
    public void externalEntityDecl(String name, String publicId, String systemId)
    throws SAXException {
    } // externalEntityDecl

    /**
     * An unparsed entity declaration.
     * 
     * @param name     The name of the entity.
     * @param publicId The public identifier of the entity, or null if not
     *                 specified.
     * @param systemId The system identifier of the entity, or null if not
     *                 specified.
     * @param notation The name of the notation.
     *
     * @throws SAXException Thrown by handler to signal an error.
     */
    public void unparsedEntityDecl(String name, String publicId, String systemId, String notation)
    throws SAXException {
    } // unparsedEntityDecl

    /**
     * A notation declaration
     * 
     * @param name     The name of the notation.
     * @param publicId The public identifier of the notation, or null if not
     *                 specified.
     * @param systemId The system identifier of the notation, or null if not
     *                 specified.
     *
     * @throws SAXException Thrown by handler to signal an error.
     */
    public void notationDecl(String name, String publicId, String systemId)
    throws SAXException {
    } // notationDecl

    /**
     * The start of a conditional section.
     * 
     * @param type The type of the conditional section. This value will
     *             either be CONDITIONAL_INCLUDE or CONDITIONAL_IGNORE.
     *
     * @throws SAXException Thrown by handler to signal an error.
     *
     * @see CONDITIONAL_INCLUDE
     * @see CONDITIONAL_IGNORE
     */
    public void startConditional(short type) throws SAXException {
    } // startConditional

    /**
     * The end of a conditional section.
     *
     * @throws SAXException Thrown by handler to signal an error.
     */
    public void endConditional() throws SAXException {
    } // endConditional

    /**
     * The end of the DTD.
     *
     * @throws SAXException Thrown by handler to signal an error.
     */
    public void endDTD() throws SAXException {
    } // endDTD

    /**
     * This method notifies the end of an entity. The DTD has the pseudo-name
     * of "[dtd]; and parameter entity names start with '%'.
     * <p>
     * <strong>Note:</strong> Since the DTD is an entity, the handler
     * will be notified of the end of the DTD entity by calling the
     * endEntity method with the entity name "[dtd]" <em>after</em> calling
     * the endDTD method.
     * 
     * @param name The name of the entity.
     *
     * @throws SAXException Thrown by handler to signal an error.
     */
    public void endEntity(String name) throws SAXException {
    }

    //
    // XMLDTDContentModelHandler methods
    //

    /**
     * The start of a content model. Depending on the type of the content
     * model, specific methods may be called between the call to the
     * startContentModel method and the call to the endContentModel method.
     * 
     * @param elementName The name of the element.
     * @param type        The content model type.
     *
     * @throws SAXException Thrown by handler to signal an error.
     *
     * @see TYPE_EMPTY
     * @see TYPE_ANY
     * @see TYPE_MIXED
     * @see TYPE_CHILDREN
     */
    public void startContentModel(String elementName, short type)
    throws SAXException {

        fQName.clear();
        fQName.setValues(null, null, elementName, null);

        fElementDecl.clear();
        fElementDecl.type = type;

        fSimpleType.clear();

    } // startContentModel

    /**
     * A referenced element in a mixed content model. If the mixed content 
     * model only allows text content, then this method will not be called
     * for that model. However, if this method is called for a mixed
     * content model, then the zero or more occurrence count is implied.
     * <p>
     * <strong>Note:</strong> This method is only called after a call to 
     * the startContentModel method where the type is TYPE_MIXED.
     * 
     * @param elementName The name of the referenced element. 
     *
     * @throws SAXException Thrown by handler to signal an error.
     *
     * @see TYPE_MIXED
     */
    public void mixedElement(String elementName) throws SAXException {
        //System.out.println("mixedElement = " + elementName);
        //fSimpleType.
       
    } // mixedElement

    /**
     * The start of a children group.
     * <p>
     * <strong>Note:</strong> This method is only called after a call to
     * the startContentModel method where the type is TYPE_CHILDREN.
     * <p>
     * <strong>Note:</strong> Children groups can be nested and have
     * associated occurrence counts.
     *
     * @throws SAXException Thrown by handler to signal an error.
     *
     * @see TYPE_CHILDREN
     */
    public void childrenStartGroup() throws SAXException {
        //System.out.println("group = " );
    } // childrenStartGroup

    /**
     * A referenced element in a children content model.
     * 
     * @param elementName The name of the referenced element.
     *
     * @throws SAXException Thrown by handler to signal an error.
     *
     * @see TYPE_CHILDREN
     */
    public void childrenElement(String elementName) throws SAXException {
        //System.out.println("chil elem = " + elementName );
    } // childrenElement

    /**
     * The separator between choices or sequences of a children content
     * model.
     * <p>
     * <strong>Note:</strong> This method is only called after a call to
     * the startContentModel method where the type is TYPE_CHILDREN.
     * 
     * @param separator The type of children separator.
     *
     * @throws SAXException Thrown by handler to signal an error.
     *
     * @see SEPARATOR_CHOICE
     * @see SEPARATOR_SEQUENCE
     * @see TYPE_CHILDREN
     */
    public void childrenSeparator(short separator) throws SAXException {
    } // childrenSeparator

    /**
     * The occurrence count for a child in a children content model.
     * <p>
     * <strong>Note:</strong> This method is only called after a call to
     * the startContentModel method where the type is TYPE_CHILDREN.
     * 
     * @param occurrence The occurrence count for the last children element
     *                   or children group.
     *
     * @throws SAXException Thrown by handler to signal an error.
     *
     * @see OCCURS_ZERO_OR_ONE
     * @see OCCURS_ZERO_OR_MORE
     * @see OCCURS_ONE_OR_MORE
     * @see TYPE_CHILDREN
     */
    public void childrenOccurrence(short occurrence) throws SAXException {
    } // childrenOccurrence

    /**
     * The end of a children group.
     * <p>
     * <strong>Note:</strong> This method is only called after a call to
     * the startContentModel method where the type is TYPE_CHILDREN.
     *
     * @see TYPE_CHILDREN
     */
    public void childrenEndGroup() throws SAXException {
    } // childrenEndGroup

    /**
     * The end of a content model.
     *
     * @throws SAXException Thrown by handler to signal an error.
     */
    public void endContentModel() throws SAXException {
         fElementDecl.setValues( fQName, 0, fElementDecl.type,  fContentModelValidator, fSimpleType );
    } // endContentModel

} // class DTDGrammar
