package com.notsecurebank.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringEscapeUtils;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import com.notsecurebank.model.Account;
import com.notsecurebank.model.User;

import org.owasp.esapi.ESAPI;

public class OperationsUtil {

    private static final Logger LOG = LogManager.getLogger(OperationsUtil.class);

    private static final String NAME_PATTERN = "^[a-zA-Z\\s'-]+$";
    private static final String EMAIL_PATTERN = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$";
    private static final String TEXT_PATTERN = "^[a-zA-Z0-9.,!?\\s'-]+$";


    public static String doTransfer(HttpServletRequest request, long creditActId, String accountIdString, double amount) {
        LOG.debug("doTransfer(HttpServletRequest, " + creditActId + ", '" + accountIdString + "', " + amount + ")");

        long debitActId = 0;

        User user = ServletUtil.getUser(request);
        String userName = user.getUsername();

        try {
            Long accountId = -1L;
            Cookie[] cookies = request.getCookies();

            Cookie notSecureBankCookie = null;

            for (Cookie cookie : cookies) {
                if (ServletUtil.NOT_SECURE_BANK_COOKIE.equals(cookie.getName())) {
                    notSecureBankCookie = cookie;
                    break;
                }
            }

            Account[] cookieAccounts = null;
            if (notSecureBankCookie == null)
                cookieAccounts = user.getAccounts();
            else
                cookieAccounts = Account.fromBase64List(notSecureBankCookie.getValue());

            try {
                accountId = Long.parseLong(accountIdString);
            } catch (NumberFormatException e) {
                // do nothing here. continue processing
                LOG.warn(e.toString());
            }

            if (accountId > 0) {
                for (Account account : cookieAccounts) {
                    if (account.getAccountId() == accountId) {
                        debitActId = account.getAccountId();
                        break;
                    }
                }
            } else {
                for (Account account : cookieAccounts) {
                    if (account.getAccountName().equalsIgnoreCase(accountIdString)) {
                        debitActId = account.getAccountId();
                        break;
                    }
                }
            }

        } catch (Exception e) {
            // do nothing
            LOG.warn(e.toString());
        }

        // we will not send an error immediately, but we need to have an
        // indication when one occurs...
        String message = null;
        if (creditActId < 0) {
            message = "Destination account is invalid";
        } else if (debitActId < 0) {
            message = "Originating account is invalid";
        } else if (amount < 0) {
            message = "Transfer amount is invalid";
        }

        // if transfer amount is zero then there is nothing to do
        if (message == null && amount > 0) {
            message = DBUtil.transferFunds(userName, creditActId, debitActId, amount);
        }

        if (message != null) {
            message = "ERROR: " + message;
            LOG.error(message);
        } else {
            message = amount + " was successfully transferred from Account " + debitActId + " into Account " + creditActId + " at " + new SimpleDateFormat().format(new Date()) + ".";
            LOG.info(message);
        }

        return message;
    }

    public static String sendFeedback(String name, String email, String subject, String comments) {
        LOG.debug("sendFeedback('" + name + "', '" + email + "', '" + subject + "', '" + comments + "')");

        email = StringEscapeUtils.escapeSql(email);
        subject = StringEscapeUtils.escapeSql(subject);
        comments = StringEscapeUtils.escapeSql(comments);

        long id = DBUtil.storeFeedback(name, email, subject, comments);
        return String.valueOf(id);

    }

    

    public static String sanitizeName(String input) throws Exception {
       if(isEmpty(input)) {
            throw new Exception("Invalid Name");
       }
        // Crea il pattern regex
        Pattern pattern = Pattern.compile(NAME_PATTERN);
        // Usa un oggetto Matcher per confrontare l'input con il pattern
        Matcher matcher = pattern.matcher(input);

        // Verifica se il nome soddisfa il pattern della whitelist
        if (matcher.matches()) {
            // Il nome è valido, restituisci il nome "sanitizzato"
            return ESAPI.encoder().encodeForHTML(input.trim());  
        } else {
            // Il nome contiene caratteri non consentiti
            throw new Exception("Invalid Name");
        }
    }

    public static String sanitizeEmail(String input) throws Exception {
        if(isEmpty(input)) {
            throw new Exception("Invalid Email");
       }
        Pattern pattern = Pattern.compile(EMAIL_PATTERN);
        Matcher matcher = pattern.matcher(input);

        if (matcher.matches()) {
            // L'indirizzo email è valido, restituisci l'indirizzo "sanitizzato"
            return ESAPI.encoder().encodeForHTML(input.trim());
        } else {
            // L'indirizzo email non è valido
            throw new Exception("Invalid Email");
        }
    }

    public static String validateText(String input) throws Exception {
         if(isEmpty(input)) {
            throw new Exception("Invalid text");
       }

        Pattern pattern = Pattern.compile(TEXT_PATTERN);
        Matcher matcher = pattern.matcher(input);

        if (matcher.matches()) {
            // Il commento è valido, restituisci il commento "validato"
            return ESAPI.encoder().encodeForHTML(input.trim());
        } else {
            // Il commento non è valido, restituisci un messaggio di errore
            throw new Exception("Invalid Text");
        }
    }

     public static boolean isEmpty(String str) {
        return str == null || str.trim().isEmpty();
     }

     public static boolean validateDate(String dateStr, String format) {
        if(isEmpty(dateStr)) {
            return false;
        }
        SimpleDateFormat sdf = new SimpleDateFormat(format);
        sdf.setLenient(false);

        try {
            Date date = sdf.parse(dateStr);
            return true;
        } catch (ParseException e) {
            return false;
        }
    }

   



}
