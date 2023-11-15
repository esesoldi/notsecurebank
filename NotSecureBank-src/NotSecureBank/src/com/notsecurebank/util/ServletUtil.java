package com.notsecurebank.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.UUID;
import java.util.regex.Pattern;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.lang.StringEscapeUtils;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.notsecurebank.model.Account;
import com.notsecurebank.model.Feedback;
import com.notsecurebank.model.User;

public class ServletUtil {
    private static final Logger LOG = LogManager.getLogger(ServletUtil.class);

    public static final String SESSION_ATTR_USER = "user";
    public static final String SESSION_ATTR_ADMIN_VALUE = "notsecurebankadmin";
    public static final String SESSION_ATTR_ADMIN_KEY = "admin";

    public static HashMap<String, String> demoProperties = null;
    public static File logFile = null;

    public static final String NOT_SECURE_BANK_COOKIE = "NotSecureBankAccounts";

    public static final String EMAIL_REGEXP = "^..*@..*\\...*$";

    public static final String LEGAL_EMAIL_ADDRESS = "^[\\w\\d\\.\\%-]+@[\\w\\d\\.\\%-]+\\.\\w{2,4}$";

    public static final Pattern XSS_REGEXP = Pattern.compile(".*(?:(<|\\%3c)(\\/|%2f|\\s|\\\u3000)*(script|img|javascript).*(>|%3e)|javascript(:|%3a)|(onblur|onchange|onfocus|onreset|onselect|onsubmit|onabort|onerror|onkeydown|onkeypress|onkeyup|onclick|ondblclick|onmousedown|onmousemove|onmouseout|onmouseover|onmouseup|onload|onunload|ondragdrop|onmove|onresize|style)=).*", Pattern.CASE_INSENSITIVE);

    public static String[] searchArticles(String query, String path) {
        LOG.debug("searchArticles('" + query + "', '" + path + "')");

        ArrayList<String> results = new ArrayList<String>();

        File file = new File(path);
        Document document;
        try {
            document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file);
            // root node
            NodeList nodes = document.getElementsByTagName("news");

            if (nodes.getLength() == 1) {
                nodes = nodes.item(0).getChildNodes();
                for (int i = 0; i < nodes.getLength(); i++) {
                    Node node = nodes.item(i);
                    if ("publication".equals(node.getNodeName())) {
                        NodeList innerNodes = node.getChildNodes();
                        String title = null;
                        Boolean isPublic = null;
                        for (int x = 0; x < innerNodes.getLength(); x++) {
                            try {
                                if ("title".equals(innerNodes.item(x).getNodeName())) {
                                    title = innerNodes.item(x).getFirstChild().getNodeValue();
                                } else if ("isPublic".equals(innerNodes.item(x).getNodeName())) {
                                    isPublic = Boolean.parseBoolean(innerNodes.item(x).getFirstChild().getNodeValue());
                                }

                                if (title != null && isPublic != null) {
                                    if (isPublic && title.contains(query)) {
                                        results.add(title);
                                    }

                                    break;
                                }
                            } catch (Exception e) {
                                LOG.warn(e.toString());
                            }
                        }
                    }
                }
            }

        } catch (Exception e) {
            LOG.warn(e.toString());
        }

        if (results.size() == 0)
            return null;

        return results.toArray(new String[results.size()]);
    }

    public static String[] searchSite(String query, String rootDir) {
        LOG.debug("searchSite('" + query + "', '" + rootDir + "')");

        ArrayList<File> matches = searchFiles(query, new File(rootDir));
        String[] results = new String[matches.size()];

        for (int i = 0; i < results.length; i++) {
            String absolutePath = matches.get(i).getAbsolutePath();
            results[i] = absolutePath.substring(rootDir.length());
        }

        return results;
    }

    /*
     * Recursive method to search a files in a directory
     */
    private static ArrayList<File> searchFiles(String query, File rootFile) {
        LOG.debug("searchFiles('" + query + "', " + (rootFile != null ? rootFile.toString() : "root file is null") + ")");

        // error checking
        if (!rootFile.canRead())
            return new ArrayList<File>();

        // if directory - recurse
        if (rootFile.isDirectory()) {
            ArrayList<File> results = new ArrayList<File>();
            File[] files = rootFile.listFiles();
            for (File file : files) {
                results.addAll(searchFiles(query, file));
            }
            return results;
        }

        // Searching data into file.
        if (rootFile.isFile()) {

            ArrayList<File> fileList = new ArrayList<File>();
            BufferedReader br = null;
            FileReader fr = null;

            try {

                String sCurrentLine;
                br = new BufferedReader(new FileReader(rootFile));

                while ((sCurrentLine = br.readLine()) != null) {
                    if (query != null && sCurrentLine.toLowerCase().contains(query.toLowerCase())) {
                        fileList.add(rootFile);
                        break;
                    }
                }

            } catch (Exception e) {
                LOG.error(e.toString());
            } finally {
                try {
                    if (br != null) {
                        br.close();
                    }
                    if (fr != null) {
                        fr.close();
                    }
                } catch (Exception ex) {
                    LOG.error(ex.toString());
                }
            }

            return fileList;
        }

        return new ArrayList<File>();
    }

    public static void addSpecialBankUsers(String username, String password, String firstname, String lastname) {
        DBUtil.addSpecialUser(username, password, firstname, lastname);
    }

    public static ArrayList<Feedback> getAllFeedback() {
        ArrayList<Feedback> feedbackList = DBUtil.getFeedback(Feedback.FEEDBACK_ALL);
        return feedbackList;
    }

    public static Feedback getFeedback(long feedbackId) {
        if (feedbackId <= 0)
            return null;

        ArrayList<Feedback> feedbackList = DBUtil.getFeedback(feedbackId);
        return feedbackList.get(0);
    }

    public static String[] getBankUsers() {
        return DBUtil.getBankUsernames();
    }

    /* Web output sanitizer */
    public static String sanitizeWeb(String data) {
        return StringEscapeUtils.escapeHtml(data);
    }

    public static String sanitizeHtmlWithRegex(String input) {
        if (XSS_REGEXP.matcher(input).matches()) {
            return "";
        }
        return input;
    }

    public static Cookie establishSession(String username, HttpSession session) {
        LOG.info("establishSession('" + username + "', HttpSession)");

        try {
            User user = DBUtil.getUserInfo(username);
            Account[] accounts = user.getAccounts();
            String accountStringList = Account.toBase64List(accounts);
            Cookie accountCookie = new Cookie(ServletUtil.NOT_SECURE_BANK_COOKIE, accountStringList);
            session.setAttribute(ServletUtil.SESSION_ATTR_USER, user);
            return accountCookie;
        } catch (SQLException e) {
            LOG.error(e.toString());
            return null;
        }
    }

    static public boolean isLoggedin(HttpServletRequest request) {
        LOG.info("Is logged in?");

        try {
            // Check user is logged in
            User user = (User) request.getSession().getAttribute(ServletUtil.SESSION_ATTR_USER);
            if (user == null) {
                LOG.info("False.");
                return false;
            }
        } catch (Exception e) {
            LOG.error(e.toString());
            LOG.info("False.");
            return false;
        }

        LOG.info("True.");
        return true;
    }

    static public User getUser(HttpServletRequest request) {
        User user = (User) request.getSession().getAttribute(ServletUtil.SESSION_ATTR_USER);
        return user;
    }

    public static boolean isPreApprovedForGoldVisa(HttpServletRequest request) {
        LOG.debug("isPreApprovedForGoldVisa");

        boolean isPreApprovedForGoldVisa = false;
        Cookie[] cookies = request.getCookies();
        if (cookies != null && cookies.length > 0) {
            for (Cookie c : cookies) {
                if ("preApprovedForGoldVisa".equals(c.getName()) && "true".equals(c.getValue())) {
                    isPreApprovedForGoldVisa = true;
                    break;
                }
            }
        }

        LOG.info("Is pre-approved for Gold Visa? " + isPreApprovedForGoldVisa);
        return isPreApprovedForGoldVisa;
    }

    public static boolean isValidEmail(String email) {
        if (email == null || email.trim().length() == 0) {
            return false;
        }

        return email.matches(LEGAL_EMAIL_ADDRESS);
    }

    public static String generateSpecialPrizeCode(HttpServletRequest request) {
        LOG.debug("generateSpecialPrizeCode");

        String specialPrizeCode = UUID.randomUUID().toString();
        request.getSession().setAttribute("specialPrizeCode", specialPrizeCode);
        return specialPrizeCode;
    }
}