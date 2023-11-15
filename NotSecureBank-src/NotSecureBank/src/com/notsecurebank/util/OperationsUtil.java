package com.notsecurebank.util;

import java.text.SimpleDateFormat;
import java.util.Date;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringEscapeUtils;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import com.notsecurebank.model.Account;
import com.notsecurebank.model.User;

public class OperationsUtil {

    private static final Logger LOG = LogManager.getLogger(OperationsUtil.class);

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

}
