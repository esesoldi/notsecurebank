package com.notsecurebank.model;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.StringTokenizer;

import org.apache.commons.codec.binary.Base64;

import com.notsecurebank.util.DBUtil;

public class Account {
    private long accountId = -1;
    private String accountName = null;
    private double balance = -1;

    public static Account getAccount(String accountNo) throws SQLException {
        if (accountNo == null || accountNo.trim().length() == 0)
            return null;

        long account = Long.parseLong(accountNo);

        return getAccount(account);
    }

    public static Account getAccount(long account) throws SQLException {
        return DBUtil.getAccount(account);
    }

    public Account(long accountId, String accountName, double balance) {
        this.accountId = accountId;
        this.accountName = accountName;
        this.balance = balance;
    }

    public long getAccountId() {
        return accountId;
    }

    public void setAccountId(int accountId) {
        this.accountId = accountId;
    }

    public double getBalance() {
        return balance;
    }

    public void setBalance(long balance) {
        this.balance = balance;
    }

    public String getAccountName() {
        return accountName;
    }

    public static Account[] fromBase64List(String b64accounts) {
        String accounts = new String(Base64.decodeBase64(b64accounts));

        StringTokenizer outerTokens = new StringTokenizer(accounts, "|");
        ArrayList<Account> accountList = new ArrayList<Account>();

        while (outerTokens.hasMoreTokens()) {
            StringTokenizer tokens = new StringTokenizer(outerTokens.nextToken(), "~");

            long acctId = -1;
            String acctName = null;
            double amt = Double.MAX_VALUE;
            if (tokens.hasMoreTokens())
                acctId = Long.valueOf(tokens.nextToken());

            if (tokens.hasMoreTokens())
                acctName = tokens.nextToken();

            if (tokens.hasMoreTokens())
                amt = Double.valueOf(tokens.nextToken());

            if (acctId > -1 && acctName != null && amt != Double.MAX_VALUE) {
                accountList.add(new Account(acctId, acctName, amt));
            }
        }

        return (accountList.toArray(new Account[accountList.size()]));
    }

    public static String toBase64List(Account[] accounts) {

        StringBuffer accountList = new StringBuffer();

        for (Account account : accounts) {
            accountList.append(account.getAccountId());
            accountList.append("~");
            accountList.append(account.getAccountName());
            accountList.append("~");
            accountList.append(account.getBalance());
            accountList.append("|");
        }

        return Base64.encodeBase64String(accountList.toString().getBytes());

    }
}
