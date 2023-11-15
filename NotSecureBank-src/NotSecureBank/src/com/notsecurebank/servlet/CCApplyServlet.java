package com.notsecurebank.servlet;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import com.notsecurebank.model.User;
import com.notsecurebank.util.DBUtil;
import com.notsecurebank.util.ServletUtil;

public class CCApplyServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger LOG = LogManager.getLogger(CCApplyServlet.class);

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        LOG.info("doPost");

        if (!ServletUtil.isLoggedin(request)) {
            response.sendRedirect("login.jsp");
            return;
        }

        User user = (User) request.getSession().getAttribute(ServletUtil.SESSION_ATTR_USER);
        String username = user.getUsername();
        String password = request.getParameter("passwd");

        if (ServletUtil.isPreApprovedForGoldVisa(request) && !user.hasGoldVisaDelivery() && password != null && password.trim().length() > 0 && DBUtil.isValidUser(username, password)) {

            if (DBUtil.setGoldVisaDelivery(username)) {
                LOG.info("Gold Visa delivery inserted for '" + username + "'.");
                request.setAttribute("gold_visa_delivery", "ok");
            } else {
                LOG.error("Error in inserting Gold Visa delivery into DB for '" + username + "'.");
            }

        } else {
            LOG.error("Gold Visa delivery prerequisites not valid for '" + username + "'.");
            request.setAttribute("gold_visa_delivery", "ko");
        }

        RequestDispatcher dispatcher = request.getRequestDispatcher("/bank/applysuccess.jsp");
        dispatcher.forward(request, response);
    }

}
