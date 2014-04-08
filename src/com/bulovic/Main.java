package com.bulovic;

import com.shutterfly.openfly.raf.CallContext;
import com.shutterfly.openfly.raf.ICallResponse;
import com.shutterfly.openfly.raf.SignedCall;
import com.shutterfly.openfly.raf.SupportedScheme;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Main {
    private static String appId = "6a0356aa0857a7898157fbdde3fbcaba";
    private static String sharedSecret = "3395ac535b31f8f4";
    private static String sflyApiHost = "ws.shutterfly.com";
    private static String sflyUploadHost = "up3.shutterfly.com";
    private static String sflyUserEmail = "eramibu@hotmail.com";
    private static String sflyUserPassword = "havoc";

    public static void main(String[] args) {
        CallContext.setDefaultAppId(appId);
        CallContext.setDefaultSharedSecret(sharedSecret);

        Scratchpad sp = new Scratchpad();
        List<String> responses = new ArrayList<>();
        sp.responses = responses;
        sp.sflyApiHost = sflyApiHost;
        sp.sflyUploadHost = sflyUploadHost;

        if (args == null) {
            responses.add("please provide a directory or list of directories");
            exit(responses);
        }

        // our directories
        for (String arg : args) {
            System.out.println("starting directory " + arg);
            Path dir = Paths.get(arg);
            // make sure it is a directory
            if (Files.notExists(dir) || !Files.isDirectory(dir)) {
                responses.add("please provide a directory");
                exit(responses);
            }

            // get all supported image files
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "*.{jpeg,jpg}")) {
                // log in
                if (!makeAuthToken(sp, sflyUserEmail, sflyUserPassword)) {
                    exit(responses);
                }
                // upload one by one
                for (Path entry : stream) {
                    String picture = entry.toString();
                    List<File> files = new ArrayList<>();
                    files.add(new File(picture));
                    String albumName = dir.getFileName().toString();
                    System.out.println("starting file " + picture);
                    upload(sp, albumName, null, files);
                    System.out.println("finished file " + picture);
                }
            } catch (Exception e) {
                e.printStackTrace(System.err);
            }
            System.out.println("finished directory " + arg);
        }

        // This prints the response strings, which have been accumulating.
        exit(responses);
    }

    static private void exit(List<String> responses) {
        if (responses != null && responses.size() >= 1) {
            for (String response : responses) {
                System.out.println();
                System.out.println(response);
            }
        }
        System.exit(0);
    }

    static private boolean isEmpty(String str) {
        return str == null || str.trim().length() <= 0;
    }

    /**
     * Calls the Shutterfly User Authentication API.
     * If successful, it sets sp.sflyUserAuthToken and sp.sflyUserid as a side effect.
     * <p/>
     * Provides a simple example of using {@link SignedCall}.
     *
     * @return 'true' for success, 'false' for failure.
     */
    static private boolean makeAuthToken(Scratchpad sp, String sflyUserEmail, String sflyUserPassword) throws IOException, URISyntaxException, XPathExpressionException, ParserConfigurationException, SAXException {
        CallContext context = new CallContext();
        context.setOverrideScheme(SupportedScheme.HTTPS);
        context.setOverrideHost(sp.sflyApiHost);
        SignedCall call = new SignedCall(context);
        call.setResourcePath("user/" + sflyUserEmail + "/auth");
        call.setContent("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "\n<entry xmlns=\"http://www.w3.org/2005/Atom\" xmlns:user=\"http://user.openfly.shutterfly.com/v1.0\">"
                + "\n  <category term=\"user\" scheme=\"http://openfly.shutterfly.com/v1.0\" />"
                + "\n  <user:password>" + sflyUserPassword + "</user:password>"
                + "\n</entry>");
        ICallResponse resp = call.httpPost();
        sp.sflyUserAuthToken = sp.getFirstValueOf(resp, "/entry/newAuthToken/text()");
        if (sp.sflyUserAuthToken == null) {
            sp.responses.add("could not get a Shutterfly user auth token from " + call.getActualUrl());
            addCallResponse(resp, sp.responses);
            return false;
        }
        sp.responses.add("got a Shutterfly user auth token, " + sp.sflyUserAuthToken);
        sp.sflyUserid = sp.getFirstValueOf(resp, "/entry/userid/text()");
        return true;
    }

    static private void addCallResponse(ICallResponse resp, List<String> responses)
            throws UnsupportedEncodingException {
        responses.add("call response: " + resp.getStatusCode() + " (" + resp.getStatusMessage() + ")");
        if (resp.getStatusCode() < 300) {
            responses.add("content type=" + resp.getContentType()
                    + ", content=" + resp.getContent());
        }
    }

    /**
     * Calls the Shutterfly Image Upload API.
     * <p/>
     * Demonstrates the features of {@link SignedCall} which support multipart/form-data POST.
     *
     * @return If upload was successful, the URI of the Shutterfly album that was just uploaded
     *         to.  Otherwise 'null'.
     */
    static private String upload(Scratchpad sp,
                                 String albumName, String folderName, List<File> files)
            throws URISyntaxException, IOException, XPathExpressionException, ParserConfigurationException, SAXException {
        CallContext context = new CallContext();
        context.setOverrideHost(sp.sflyUploadHost);
        SignedCall call = new SignedCall(context);
        call.setResourcePath("images");
        call.addMultiPartParameter("AuthenticationID", sp.sflyUserAuthToken);
        if (!isEmpty(albumName)) {
            call.addMultiPartParameter("Image.AlbumName", albumName);
        }
        if (!isEmpty(folderName)) {
            call.addMultiPartParameter("Image.FolderName", folderName);
        }
        for (File file : files) {
            call.addMultiPartParameter("Image.Data", "image/jpeg", file.getName(), file);
        }
        ICallResponse resp = call.httpPost();
        String errCode = sp.getFirstValueOf(resp, "/feed/errCode/text()");
        if (errCode == null) {
            sp.responses.add("invalid response, could not even get an errCode from " + call.getActualUrl());
            addCallResponse(resp, sp.responses);
            return null;
        }
        String errMessage = sp.getFirstValueOf(resp, "/feed/errMessage/text()");
        String numSuccess = sp.getFirstValueOf(resp, "/feed/numSuccess/text()");
        String numFail = sp.getFirstValueOf(resp, "/feed/numFail/text()");
        String albumUrl = sp.getFirstValueOf(resp, "/feed/link[@rel = 'related']/@href");
        sp.responses.add("upload: errCode=" + errCode
                + ", errMessage=" + errMessage
                + ", numSuccess=" + numSuccess
                + ("0".equals(numFail) ? "" : ", numFail=" + numFail)
        );
        return albumUrl;
    }

    /**
     * This class is just a way to hold certain work-in-progress data values, plus
     * some associated utility methods, like those for performing XPath queries.
     *
     * @author jcarty
     */
    static private class Scratchpad {
        List<String> responses;
        String sflyApiHost;
        String sflyUploadHost;
        String sflyUserAuthToken;
        String sflyUserid;
        // Some cached items... as long as these are instance-level, don't worry about memory leaks.
        private DocumentBuilder builder;
        private XPath xpath;
        private Map<String, Document> docTrees = new HashMap<String, Document>();
        private Map<String, XPathExpression> compiledXpex = new HashMap<String, XPathExpression>();

        Scratchpad() {
        }

        /**
         * @return A {@link DocumentBuilder} object; one that is cached in this instance.
         */
        DocumentBuilder getDocumentBuilder()
                throws ParserConfigurationException, SAXException, IOException {
            if (this.builder == null) {
                DocumentBuilderFactory dbfactory = DocumentBuilderFactory.newInstance();
                dbfactory.setNamespaceAware(false);
                this.builder = dbfactory.newDocumentBuilder();
            }
            return this.builder;
        }

        /**
         * @return A {@link XPath} object; one that is cached in this instance.
         */
        XPath getXpath() {
            if (this.xpath == null) {
                XPathFactory xpfactory = XPathFactory.newInstance();
                this.xpath = xpfactory.newXPath();
            }
            return this.xpath;
        }

        /**
         * @param resp      A {@link ICallResponse} object, acquired by running a {@link SignedCall}.
         * @param xpathExpr An XPath expression to be searched in the XML of the response.
         * @return The value of the XPath expression, or 'null' if the XPath expression cannot
         *         be found in the response.
         */
        String getFirstValueOf(ICallResponse resp, String xpathExpr)
                throws XPathExpressionException, ParserConfigurationException, SAXException, IOException {
            if (resp.getStatusCode() >= 300) {
                return null; // unsuccessful call
            }
            if (resp.getContentType() != null && resp.getContentType().indexOf("xml") < 0) {
                return null; // not xml content
            }
            final String xml = resp.getContent();
            final String ret = getFirstValueOf(xml, xpathExpr);
            return ret;
        }

        /**
         * @param xml       Some XML text to be searched.
         * @param xpathExpr An XPath expression to be searched in the XML.
         * @return The value of the XPath expression, or 'null' if the XPath expression cannot
         *         be found in the XML.
         */
        String getFirstValueOf(String xml, String xpathExpr)
                throws ParserConfigurationException, SAXException, IOException, XPathExpressionException {
            final NodeList nodes = getNodeListOf(xml, xpathExpr);
            final String ret = getFirstValueOf(nodes);
            return ret;
        }

        /**
         * @param xml       Some XML text to be searched.
         * @param xpathExpr An XPath expression to be searched in the XML.
         * @return A {@link NodeList} representing the value of the XPath expression, or 'null'
         *         if the XPath expression cannot be found in the XML.
         */
        NodeList getNodeListOf(String xml, String xpathExpr)
                throws ParserConfigurationException, SAXException, IOException, XPathExpressionException {
            Document doc = docTrees.get(xml);
            if (doc == null) {
                final DocumentBuilder builder = getDocumentBuilder();
                doc = builder.parse(new InputSource(new StringReader(xml)));
                docTrees.put(xml, doc);
            }
            final NodeList ret = getNodeListOf(doc, xpathExpr);
            return ret;
        }

        /**
         * @param contextNode A {@link Node} to be used as the starting point (the context node)
         *                    for a search.
         * @param xpathExpr   An XPath expression to be searched in the node.
         * @return A {@link NodeList} representing the value of the XPath expression, or 'null'
         *         if the XPath expression cannot be found in the node.
         */
        NodeList getNodeListOf(Node contextNode, String xpathExpr) throws XPathExpressionException {
            XPathExpression xpex = compiledXpex.get(xpathExpr);
            if (xpex == null) {
                final XPath xpath = getXpath();
                xpex = xpath.compile(xpathExpr);
                compiledXpex.put(xpathExpr, xpex);
            }
            final NodeList nodes = (NodeList) xpex.evaluate(contextNode, XPathConstants.NODESET);
            return nodes;
        }

        /**
         * @param nodes A {@link NodeList} to be examined.
         * @return The value of the first node in the list, or 'null' if there is none.
         */
        String getFirstValueOf(NodeList nodes) {
            if (nodes == null || nodes.getLength() <= 0) {
                return null;
            }
            final Node node = nodes.item(0);
            final String ret = node.getNodeValue();
            return ret;
        }

        /**
         * @param contextNode A {@link Node} to be used as the starting point (the context node)
         *                    for a search.
         * @param xpathExpr   An XPath expression to be searched in the node.
         * @return The value of the first node in the search result, or 'null' if there is none.
         */
        String getFirstValueOf(Node contextNode, String xpathExpr) throws XPathExpressionException {
            NodeList nodes = getNodeListOf(contextNode, xpathExpr);
            final String ret = getFirstValueOf(nodes);
            return ret;
        }
    }
}
