package com.notsecurebank.servlet;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import com.notsecurebank.util.OperationsUtil;
import com.notsecurebank.util.ServletUtil;

public class TransferServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger LOG = LogManager.getLogger(TransferServlet.class);

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        LOG.info("doGet");

        doPost(req, resp);
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        LOG.info("doPost");

        if (!ServletUtil.isLoggedin(request)) {
            response.sendRedirect("login.jsp");
            return;
        }

        String accountIdString = request.getParameter("fromAccount");
        long creditActId = Long.parseLong(request.getParameter("toAccount"));
        double amount = Double.valueOf(request.getParameter("transferAmount"));

        String message = OperationsUtil.doTransfer(request, creditActId, accountIdString, amount);

        RequestDispatcher dispatcher = request.getRequestDispatcher("transfer.jsp");
        request.setAttribute("message", message);
        dispatcher.forward(request, response);
    }

}
