package burp;

import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
// Empty Burp Extension from https://github.com/alexlauerman/EmptyBurpExtension

public class BurpExtender implements burp.IBurpExtender, burp.IHttpListener
{
    private burp.IExtensionHelpers helpers;
    private burp.IHttpListener listener;
    private PrintWriter stdout;
    private PrintWriter stderr;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // set our extension name
        callbacks.setExtensionName("MD5 Header Updater");

        // obtain our output and error streams
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(),true);

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // register ourselves as an HTTP listener
        callbacks.registerHttpListener((IHttpListener) this);
    }

    // MD5 from https://javarevisited.blogspot.com/2013/03/generate-md5-hash-in-java-string-byte-array-example-tutorial.html
    public static String md5Java(String body){
        String digest = null;
        MessageDigest md = null;
        try
        {
            md = MessageDigest.getInstance("MD5");
            //md = MessageDigest.getInstance("SHA-1");
            //md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
        byte[] hash = new byte[0];
        try
        {
            hash = md.digest(body.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e)
        {
            e.printStackTrace();
        }

        //converting byte array to Hexadecimal String
        StringBuilder sb = new StringBuilder(2*hash.length);
        for(byte b : hash) {
            sb.append(String.format("%02x", b & 0xff));
        }
        digest = sb.toString();

        return digest;
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, burp.IHttpRequestResponse message)
    {
        if(messageIsRequest){ //&& toolFlag == IBurpExtenderCallbacks.TOOL_PROXY
            byte[] messageInfo = message.getRequest();
            IRequestInfo rqInfo = helpers.analyzeRequest(message);
            String reqBody = (new String(messageInfo)).substring(rqInfo.getBodyOffset());
            String reqHash = md5Java(reqBody);
            List<String> headers = rqInfo.getHeaders();
            //Remove current header
            for (int i = 0; i < headers.size(); i++){
                if (headers.get(i).startsWith("Hash:")){
                    headers.remove(i);
                }
            }
            headers.add("Hash: " + reqHash);
            byte[] newMessage = helpers.buildHttpMessage(headers, reqBody.getBytes());
            message.setRequest(newMessage);
        }
    }
}
