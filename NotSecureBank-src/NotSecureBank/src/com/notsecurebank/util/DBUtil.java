package com.notsecurebank.util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import com.notsecurebank.model.Account;
import com.notsecurebank.model.Feedback;
import com.notsecurebank.model.Transaction;
import com.notsecurebank.model.User;
import com.notsecurebank.model.User.Role;

public class DBUtil {

    private static final Logger LOG = LogManager.getLogger(DBUtil.class);

    public static final String CREDIT_CARD_ACCOUNT_NAME = "Credit Card";
    public static final String CHECKING_ACCOUNT_NAME = "Checking";
    public static final String SAVINGS_ACCOUNT_NAME = "Savings";

    public static final double CASH_ADVANCE_FEE = 2.50;

    private static DBUtil instance = null;
    private Connection connection = null;
    private DataSource dataSource = null;

    // private constructor
    private DBUtil() {

        String dataSourceName = "jdbc/nsb";

        try {
            Context initialContext = new InitialContext();
            Context environmentContext = (Context) initialContext.lookup("java:comp/env");
            dataSource = (DataSource) environmentContext.lookup(dataSourceName.trim());
        } catch (Exception e) {
            LOG.fatal(e.toString());
        }

    }

    private static Connection getConnection() throws SQLException {

        if (instance == null)
            instance = new DBUtil();

        if (instance.connection == null || instance.connection.isClosed()) {

            // If there is a custom data source configured use it to initialize.
            if (instance.dataSource != null) {
                LOG.debug("Getting the DB connection.");
                instance.connection = instance.dataSource.getConnection();
                return instance.connection;
            } else {
                LOG.fatal("Datasource is null!");
            }

        }

        return instance.connection;
    }

    public static ArrayList<Feedback> getFeedback(long feedbackId) {
        LOG.debug("getFeedback(" + feedbackId + ")");

        ArrayList<Feedback> feedbackList = new ArrayList<Feedback>();

        try {
            Connection connection = getConnection();
            Statement statement = connection.createStatement();

            String query = "SELECT * FROM FEEDBACK";

            if (feedbackId != Feedback.FEEDBACK_ALL) {
                query = query + " WHERE FEEDBACK_ID = " + feedbackId + "";
            }

            ResultSet resultSet = statement.executeQuery(query);

            while (resultSet.next()) {
                String name = resultSet.getString("NAME");
                String email = resultSet.getString("EMAIL");
                String subject = resultSet.getString("SUBJECT");
                String message = resultSet.getString("COMMENTS");
                long id = resultSet.getLong("FEEDBACK_ID");
                Feedback feedback = new Feedback(id, name, email, subject, message);
                feedbackList.add(feedback);
            }
        } catch (SQLException e) {
            LOG.error("Error retrieving feedback > " + e.toString());
        }

        return feedbackList;
    }

    public static boolean hasGoldVisaDelivery(String username) {
        LOG.debug("hasGoldVisaDelivery('" + username + "')");

        if (username == null || username.trim().length() == 0)
            return true;

        boolean hasGoldVisaDelivery = false;

        try {

            Connection connection = getConnection();
            PreparedStatement preparedStatement = connection.prepareStatement("SELECT COUNT(*) FROM GOLD_VISA_DELIVERY WHERE USER_ID = ?");
            preparedStatement.setString(1, username);

            ResultSet resultSet = preparedStatement.executeQuery();

            if (resultSet.next()) {
                if (resultSet.getInt(1) > 0) {
                    hasGoldVisaDelivery = true;
                }
            }

        } catch (Exception e) {
            hasGoldVisaDelivery = true;
            LOG.error(e.toString());
        }

        LOG.info("'" + username + "' has Gold Visa delivery? " + hasGoldVisaDelivery);
        return hasGoldVisaDelivery;
    }

    public static boolean setGoldVisaDelivery(String username) {
        LOG.debug("setGoldVisaDelivery('" + username + "')");

        if (username == null || username.trim().length() == 0)
            return false;

        boolean success = false;

        try {

            Connection connection = getConnection();
            PreparedStatement preparedStatement = connection.prepareStatement("INSERT INTO GOLD_VISA_DELIVERY (USER_ID) VALUES (?)");
            preparedStatement.setString(1, username);
            preparedStatement.executeUpdate();
            success = true;

        } catch (Exception e) {
            success = false;
            LOG.error(e.toString());
        }

        return success;
    }

    private static boolean isValidLogin(String query, String username, String password) {
        LOG.debug("isValidLogin('" + query + "', '" + username + "', '" + password + "')");

        if (username == null || password == null || username.trim().length() == 0 || password.trim().length() == 0)
            return false;

        boolean isValidUser = false;

        try {

            Connection connection = getConnection();
            PreparedStatement preparedStatement = connection.prepareStatement(query);
            preparedStatement.setString(1, username);
            preparedStatement.setString(2, password);

            ResultSet resultSet = preparedStatement.executeQuery();

            if (resultSet.next()) {
                if (resultSet.getInt(1) > 0) {
                    isValidUser = true;
                }
            }

        } catch (Exception e) {
            isValidUser = false;
            LOG.error(e.toString());
        }

        return isValidUser;
    }

    public static boolean isValidUser(String username, String password) {
        String query = "SELECT COUNT(*) FROM PEOPLE WHERE ROLE = 'user' AND USER_ID = ? AND PASSWORD = ?";
        return isValidLogin(query, username, password);
    }

    public static boolean isValidAdmin(String adminUsername, String adminPassword) {
        String query = "SELECT COUNT(*) FROM PEOPLE WHERE ROLE = 'admin' AND USER_ID = ? AND PASSWORD = ?";
        return isValidLogin(query, adminUsername, adminPassword);
    }

    public static boolean isValidApiUser(String username, String password) {
        String query = "SELECT COUNT(*) FROM PEOPLE WHERE USER_ID = ? AND PASSWORD = ?";
        return isValidLogin(query, username, password);
    }

    public static User getUserInfo(String username) throws SQLException {
        LOG.debug("getUserInfo('" + username + "')");

        if (username == null || username.trim().length() == 0)
            return null;

        Connection connection = getConnection();
        Statement statement = connection.createStatement();
        ResultSet resultSet = statement.executeQuery("SELECT FIRST_NAME,LAST_NAME,ROLE,EMAIL FROM PEOPLE WHERE USER_ID = '" + username + "' ");

        String firstName = null;
        String lastName = null;
        String roleString = null;
        String email = null;
        if (resultSet.next()) {
            firstName = resultSet.getString("FIRST_NAME");
            lastName = resultSet.getString("LAST_NAME");
            roleString = resultSet.getString("ROLE");
            email = resultSet.getString("EMAIL");
        }

        if (firstName == null || lastName == null)
            return null;

        User user = new User(username, firstName, lastName, email);

        if (roleString.equalsIgnoreCase("admin"))
            user.setRole(Role.Admin);

        return user;
    }

    public static Account[] getAccounts(String username) throws SQLException {
        LOG.debug("getAccounts('" + username + "')");

        if (username == null || username.trim().length() == 0)
            return null;

        Connection connection = getConnection();
        Statement statement = connection.createStatement();
        ResultSet resultSet = statement.executeQuery("SELECT ACCOUNT_ID, ACCOUNT_NAME, BALANCE FROM ACCOUNTS WHERE USERID = '" + username + "' ");

        ArrayList<Account> accounts = new ArrayList<Account>(3);
        while (resultSet.next()) {
            long accountId = resultSet.getLong("ACCOUNT_ID");
            String name = resultSet.getString("ACCOUNT_NAME");
            double balance = resultSet.getDouble("BALANCE");
            Account newAccount = new Account(accountId, name, balance);
            accounts.add(newAccount);
        }

        return accounts.toArray(new Account[accounts.size()]);
    }

    public static String transferFunds(String username, long creditActId, long debitActId, double amount) {
        LOG.debug("transferFunds('" + username + "', " + creditActId + ", " + debitActId + ", " + amount + ")");

        try {

            User user = getUserInfo(username);

            Connection connection = getConnection();
            Statement statement = connection.createStatement();

            Account debitAccount = Account.getAccount(debitActId);
            Account creditAccount = Account.getAccount(creditActId);

            if (debitAccount == null) {
                LOG.error("Originating account is invalid");
                return "Originating account is invalid";
            }

            if (creditAccount == null) {
                LOG.error("Destination account is invalid");
                return "Destination account is invalid";
            }

            java.sql.Timestamp date = new Timestamp(new java.util.Date().getTime());

            long userCC = user.getCreditCardNumber();

            /*
             * this is the account that the payment will be made from, thus
             * negative amount!
             */
            double debitAmount = -amount;
            /*
             * this is the account that the payment will be made to, thus
             * positive amount!
             */
            double creditAmount = amount;

            /*
             * Credit card account balance is the amount owed, not amount owned
             * (reverse of other accounts). Therefore we have to process
             * balances differently
             */
            if (debitAccount.getAccountId() == userCC)
                debitAmount = -debitAmount;

            // create transaction record
            statement.execute("INSERT INTO TRANSACTIONS (ACCOUNTID, DATE, TYPE, AMOUNT) VALUES (" + debitAccount.getAccountId() + ",'" + date + "'," + ((debitAccount.getAccountId() == userCC) ? "'Cash Advance'" : "'Withdrawal'") + "," + debitAmount + ")," + "(" + creditAccount.getAccountId() + ",'" + date + "'," + ((creditAccount.getAccountId() == userCC) ? "'Payment'" : "'Deposit'") + "," + creditAmount + ")");

            LOG.info("Debit: " + debitAccount.getAccountId() + " - " + debitAccount.getAccountName() + ", Credit: " + creditAccount.getAccountId() + " - " + creditAccount.getAccountName() + ", Amount: " + amount);

            if (creditAccount.getAccountId() == userCC)
                creditAmount = -creditAmount;

            // add cash advance fee since the money transfer was made from the
            // credit card
            if (debitAccount.getAccountId() == userCC) {
                statement.execute("INSERT INTO TRANSACTIONS (ACCOUNTID, DATE, TYPE, AMOUNT) VALUES (" + debitAccount.getAccountId() + ",'" + date + "','Cash Advance Fee'," + CASH_ADVANCE_FEE + ")");
                debitAmount += CASH_ADVANCE_FEE;
                LOG.info("Cash advance fee. Credit Card: " + String.valueOf(userCC) + ", Fee: " + CASH_ADVANCE_FEE);
            }

            // update account balances
            statement.execute("UPDATE ACCOUNTS SET BALANCE = " + (debitAccount.getBalance() + debitAmount) + " WHERE ACCOUNT_ID = " + debitAccount.getAccountId());
            statement.execute("UPDATE ACCOUNTS SET BALANCE = " + (creditAccount.getBalance() + creditAmount) + " WHERE ACCOUNT_ID = " + creditAccount.getAccountId());

            return null;

        } catch (SQLException e) {
            LOG.error(e.toString());
            return "Transaction failed. Please try again later.";
        }
    }

    public static Transaction[] getTransactions(String startDate, String endDate, Account[] accounts, int rowCount) throws SQLException {
        LOG.debug("getTransactions('" + startDate + "', '" + endDate + "', " + (accounts != null ? "accounts.length=" + accounts.length : "accounts array is null") + ", " + rowCount + ")");

        if (accounts == null || accounts.length == 0)
            return null;

        Connection connection = getConnection();

        Statement statement = connection.createStatement();

        if (rowCount > 0)
            statement.setMaxRows(rowCount);

        StringBuffer acctIds = new StringBuffer();
        acctIds.append("ACCOUNTID = " + accounts[0].getAccountId());
        for (int i = 1; i < accounts.length; i++) {
            acctIds.append(" OR ACCOUNTID = " + accounts[i].getAccountId());
        }

        String dateString = null;

        if (startDate != null && startDate.length() > 0 && endDate != null && endDate.length() > 0) {
            dateString = "DATE BETWEEN '" + startDate + " 00:00:00' AND '" + endDate + " 23:59:59'";
        } else if (startDate != null && startDate.length() > 0) {
            dateString = "DATE > '" + startDate + " 00:00:00'";
        } else if (endDate != null && endDate.length() > 0) {
            dateString = "DATE < '" + endDate + " 23:59:59'";
        }

        String query = "SELECT * FROM TRANSACTIONS WHERE (" + acctIds.toString() + ") " + ((dateString == null) ? "" : "AND (" + dateString + ") ") + "ORDER BY DATE DESC";
        ResultSet resultSet = null;

        try {
            resultSet = statement.executeQuery(query);
        } catch (SQLException e) {
            LOG.error(e.toString());

            int errorCode = e.getErrorCode();
            if (errorCode == 30000)
                throw new SQLException("Date-time query must be in the format of yyyy-mm-dd HH:mm:ss", e);

            throw e;
        }
        ArrayList<Transaction> transactions = new ArrayList<Transaction>();
        while (resultSet.next()) {
            int transId = resultSet.getInt("TRANSACTION_ID");
            long actId = resultSet.getLong("ACCOUNTID");
            Timestamp date = resultSet.getTimestamp("DATE");
            String desc = resultSet.getString("TYPE");
            double amount = resultSet.getDouble("AMOUNT");
            transactions.add(new Transaction(transId, actId, date, desc, amount));
        }

        return transactions.toArray(new Transaction[transactions.size()]);
    }

    public static String[] getBankUsernames() {
        LOG.debug("getBankUsernames()");

        try {
            Connection connection = getConnection();
            Statement statement = connection.createStatement();
            // at the moment this query limits transfers to
            // transfers between two user accounts
            ResultSet resultSet = statement.executeQuery("SELECT USER_ID FROM PEOPLE");

            ArrayList<String> users = new ArrayList<String>();

            while (resultSet.next()) {
                String name = resultSet.getString("USER_ID");
                users.add(name);
            }

            return users.toArray(new String[users.size()]);
        } catch (SQLException e) {
            LOG.error(e.toString());
            return new String[0];
        }
    }

    public static Account getAccount(long accountNo) throws SQLException {
        LOG.debug("getAccount(" + accountNo + ")");

        Connection connection = getConnection();
        Statement statement = connection.createStatement();
        ResultSet resultSet = statement.executeQuery("SELECT ACCOUNT_NAME, BALANCE FROM ACCOUNTS WHERE ACCOUNT_ID = " + accountNo + " ");

        ArrayList<Account> accounts = new ArrayList<Account>(3);
        while (resultSet.next()) {
            String name = resultSet.getString("ACCOUNT_NAME");
            double balance = resultSet.getDouble("BALANCE");
            Account newAccount = new Account(accountNo, name, balance);
            accounts.add(newAccount);
        }

        if (accounts.size() == 0)
            return null;

        return accounts.get(0);
    }

    public static String addAccount(String username, String acctType) {
        LOG.debug("addAccount('" + username + "', '" + acctType + "')");

        try {
            Connection connection = getConnection();
            Statement statement = connection.createStatement();
            statement.execute("INSERT INTO ACCOUNTS (USERID,ACCOUNT_NAME,BALANCE) VALUES ('" + username + "','" + acctType + "', 0)");
            return null;
        } catch (SQLException e) {
            LOG.error(e.toString());
            return e.toString();
        }
    }

    public static String addSpecialUser(String username, String password, String firstname, String lastname) {
        LOG.debug("addSpecialUser('" + username + "', '" + password + "', '" + firstname + "', '" + lastname + "')");

        try {
            Connection connection = getConnection();
            Statement statement = connection.createStatement();
            statement.execute("INSERT INTO SPECIAL_CUSTOMERS (USER_ID,PASSWORD,FIRST_NAME,LAST_NAME,ROLE) VALUES ('" + username + "','" + password + "', '" + firstname + "', '" + lastname + "','user')");
            return null;
        } catch (SQLException e) {
            LOG.error(e.toString());
            return e.toString();
        }
    }

    public static String addUser(String username, String password, String firstname, String lastname, String email) {
        LOG.debug("addUser('" + username + "', '" + password + "', '" + firstname + "', '" + lastname + "', '" + email + "')");

        try {
            Connection connection = getConnection();
            Statement statement = connection.createStatement();
            statement.execute("INSERT INTO PEOPLE (USER_ID,PASSWORD,FIRST_NAME,LAST_NAME,ROLE,EMAIL) VALUES ('" + username + "','" + password + "', '" + firstname + "', '" + lastname + "','user', '" + email + "')");
            return null;
        } catch (SQLException e) {
            LOG.error(e.toString());
            return e.toString();
        }
    }

    public static String changePassword(String username, String password) {
        LOG.debug("changePassword('" + username + "', '" + password + "')");

        try {
            Connection connection = getConnection();
            Statement statement = connection.createStatement();
            statement.execute("UPDATE PEOPLE SET PASSWORD = '" + password + "' WHERE USER_ID = '" + username + "'");
            return null;
        } catch (SQLException e) {
            LOG.error(e.toString());
            return e.toString();
        }
    }

    public static long storeFeedback(String name, String email, String subject, String comments) {
        LOG.debug("storeFeedback('" + name + "', '" + email + "', '" + subject + "', '" + comments + "')");

        try {
            Connection connection = getConnection();
            Statement statement = connection.createStatement();
            statement.execute("INSERT INTO FEEDBACK (NAME,EMAIL,SUBJECT,COMMENTS) VALUES ('" + name + "', '" + email + "', '" + subject + "', '" + comments + "')", Statement.RETURN_GENERATED_KEYS);
            ResultSet rs = statement.getGeneratedKeys();
            long id = -1;
            if (rs.next()) {
                id = rs.getLong(1);
            }
            return id;
        } catch (SQLException e) {
            LOG.error(e.toString());
            return -1;
        }
    }

    public static String addSubscription(String email) throws SQLException {
        LOG.debug("addSubscription('" + email + "')");

        String registeredUser = null;

        try {

            Connection connection = getConnection();
            PreparedStatement preparedStatement = connection.prepareStatement("SELECT COUNT(*) FROM SUBSCRIPTION WHERE EMAIL = ?");
            preparedStatement.setString(1, email);

            ResultSet resultSet = preparedStatement.executeQuery();

            boolean exists = false;
            if (resultSet.next()) {
                if (resultSet.getInt(1) > 0) {
                    LOG.debug("The subcription exists.");
                    exists = true;
                }
            }

            if (!exists) {
                preparedStatement = connection.prepareStatement("INSERT INTO SUBSCRIPTION (EMAIL) VALUES (?)");
                preparedStatement.setString(1, email);
                preparedStatement.executeUpdate();
            }

            preparedStatement = connection.prepareStatement("SELECT USER_ID FROM PEOPLE WHERE EMAIL = ? AND ROLE = 'user'");
            preparedStatement.setString(1, email);
            resultSet = preparedStatement.executeQuery();

            if (resultSet.next()) {
                String readUser = resultSet.getString("USER_ID");
                if (readUser != null) {
                    LOG.debug("An already registered user exists.");
                    registeredUser = readUser;
                }
            }

        } catch (SQLException e) {
            LOG.error(e.toString());
            throw e;
        }

        return registeredUser;
    }

    public static boolean isSpecialPrizeActive() {
        LOG.debug("isSpecialPrizeActive()");

        boolean isSpecialPrizeActive = false;

        try {

            Connection connection = getConnection();
            PreparedStatement preparedStatement = connection.prepareStatement("SELECT COUNT(*) FROM CONFIGURATION WHERE CONF_KEY = 'specialPrizeActive' AND CONF_KEY = 'true'");

            ResultSet resultSet = preparedStatement.executeQuery();

            if (resultSet.next()) {
                if (resultSet.getInt(1) > 0) {
                    isSpecialPrizeActive = true;
                }
            }

        } catch (Exception e) {
            isSpecialPrizeActive = false;
            LOG.error(e.toString());
        }

        LOG.info("Is special prize active? " + isSpecialPrizeActive);
        return isSpecialPrizeActive;
    }

    public static void addSpecialPrize(String username, String code, String prize) throws SQLException {
        LOG.debug("addSpecialPrize()");

        try {

            Connection connection = getConnection();
            PreparedStatement preparedStatement = connection.prepareStatement("INSERT INTO SPECIAL_PRIZE (USER_ID, CODE, PRIZE) VALUES (?, ?, ?)");
            preparedStatement.setString(1, username);
            preparedStatement.setString(2, code);
            preparedStatement.setString(3, prize);
            preparedStatement.executeUpdate();

        } catch (SQLException e) {
            LOG.error(e.toString());
            throw e;
        }
    }
}