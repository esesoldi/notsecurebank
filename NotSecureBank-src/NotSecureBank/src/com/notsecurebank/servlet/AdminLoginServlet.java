package com.notsecurebank.servlet;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
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

public class AdminLoginServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    private static final Logger LOG = LogManager.getLogger(AdminLoginServlet.class);

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        LOG.info("doPost");

        String username = request.getParameter("username");
        String password = request.getParameter("password");
        if (username == null || password == null) {
            LOG.warn("No username/password.");
            response.sendRedirect(request.getContextPath() + "/admin/login.jsp");
            return;
        } else if (!DBUtil.isValidAdmin(username.trim(), password.trim())) {
            LOG.fatal("Admin login failed.");
            request.setAttribute("loginError", "Login failed.");
            RequestDispatcher dispatcher = request.getRequestDispatcher("/admin/login.jsp");
            dispatcher.forward(request, response);
            return;
        } else {
            LOG.info("Admin login success.");

            // Setting admin session.
            HttpSession session = request.getSession(true);
            session.setAttribute(ServletUtil.SESSION_ATTR_ADMIN_KEY, ServletUtil.SESSION_ATTR_ADMIN_VALUE);

            // Setting normal user session.
            try {
                Cookie accountCookie = ServletUtil.establishSession(username, session);
                response.addCookie(accountCookie);
            } catch (Exception ex) {
                LOG.error(ex.toString());
                response.sendError(500);
            }

            response.sendRedirect(request.getContextPath() + "/admin/admin.jsp");
        }
    }
}
