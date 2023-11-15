package com.notsecurebank.servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import com.notsecurebank.util.DBUtil;
import com.notsecurebank.util.ServletUtil;

public class AdminServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger LOG = LogManager.getLogger(AdminServlet.class);

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        LOG.info("doPost");

        String message = null;

        // add account
        if (request.getRequestURL().toString().endsWith("addAccount")) {
            LOG.info("addAccount");

            String username = request.getParameter("username");
            String acctType = request.getParameter("accttypes");
            if (username == null || acctType == null || username.trim().length() == 0 || acctType.trim().length() == 0) {
                LOG.error("Inserted data null or empty for addAccount operation.");
                message = "An error has occurred. Please try again later.";
            } else {
                String error = DBUtil.addAccount(username, acctType);
                if (error != null)
                    message = error;
            }
        }

        // add user
        else if (request.getRequestURL().toString().endsWith("addUser")) {
            LOG.info("addUser");

            String firstname = request.getParameter("firstname");
            String lastname = request.getParameter("lastname");
            String username = request.getParameter("username");
            String email = request.getParameter("email");
            String password1 = request.getParameter("password1");
            String password2 = request.getParameter("password2");
            if (firstname == null || firstname.trim().length() == 0 || lastname == null || lastname.trim().length() == 0 || username == null || username.trim().length() == 0 || email == null || email.trim().length() == 0 || password1 == null || password1.trim().length() == 0 || password2 == null || password2.trim().length() == 0) {
                LOG.error("Inserted data null or empty for addUser operation.");
                message = "An error has occurred. Please try again later.";
            }

            if (message == null && !password1.equals(password2)) {
                LOG.error("Entered passwords did not match for addUser operation.");
                message = "Entered passwords did not match.";
            }

            if (!ServletUtil.isValidEmail(email)) {
                LOG.error("Entered email is not valid.");
                message = "Entered email is not valid.";
            }

            if (message == null) {
                String error = DBUtil.addUser(username, password1, firstname, lastname, email);

                if (error != null)
                    message = error;
            }

        }

        // change password
        else if (request.getRequestURL().toString().endsWith("changePassword")) {
            LOG.info("changePassword");

            String username = request.getParameter("username");
            String password1 = request.getParameter("password1");
            String password2 = request.getParameter("password2");
            if (username == null || username.trim().length() == 0 || password1 == null || password1.trim().length() == 0 || password2 == null || password2.trim().length() == 0) {
                LOG.error("Inserted data null or empty for changePassword operation.");
                message = "An error has occurred. Please try again later.";
            }

            if (message == null && !password1.equals(password2)) {
                LOG.error("Entered passwords did not match for changePassword operation.");
                message = "Entered passwords did not match.";
            }

            if (message == null) {
                String error = DBUtil.changePassword(username, password1);

                if (error != null)
                    message = error;
            }
        } else {
            LOG.error("Unknown operation: '" + request.getRequestURL().toString() + "'.");
            message = "An error has occurred. Please try again later.";
        }

        if (message != null)
            message = "Error: " + message;
        else
            message = "Requested operation has completed successfully.";

        request.getSession().setAttribute("message", message);
        response.sendRedirect("admin.jsp");
        return;
    }

}
