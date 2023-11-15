package com.notsecurebank.servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import com.notsecurebank.util.DBUtil;
import com.notsecurebank.util.ServletUtil;

public class LoginServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger LOG = LogManager.getLogger(LoginServlet.class);

    public LoginServlet() {
        super();
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        LOG.info("doGet");

        // log out
        try {
            LOG.info("Logout.");
            HttpSession session = request.getSession(false);
            session.removeAttribute(ServletUtil.SESSION_ATTR_USER); // Removing user.
            session.removeAttribute(ServletUtil.SESSION_ATTR_ADMIN_KEY); // Removing admin.
        } catch (Exception e) {
            LOG.warn(e.toString());
        } finally {
            response.sendRedirect("index.jsp");
        }

    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        LOG.info("doPost");

        // log in
        // Create session if there isn't one:
        HttpSession session = request.getSession(true);

        String username = null;

        try {
            username = request.getParameter("uid");
            if (username != null)
                username = username.trim().toLowerCase();

            String password = request.getParameter("passw");
            password = password.trim();

            if (!DBUtil.isValidUser(username, password)) {
                LOG.error("Login failed >>> User: " + username + " >>> Password: " + password);
                throw new Exception("Login Failed: We're sorry, but this username or password was not found in our system. Please try again.");
            }
        } catch (Exception ex) {
            LOG.error(ex.toString());
            request.getSession(true).setAttribute("loginError", ex.getLocalizedMessage());
            response.sendRedirect("login.jsp");
            return;
        }

        try {
            Cookie accountCookie = ServletUtil.establishSession(username, session);
            response.addCookie(accountCookie);
            response.sendRedirect(request.getContextPath() + "/bank/main.jsp");
        } catch (Exception ex) {
            LOG.error(ex.toString());
            response.sendError(500);
        }

        return;
    }

}
