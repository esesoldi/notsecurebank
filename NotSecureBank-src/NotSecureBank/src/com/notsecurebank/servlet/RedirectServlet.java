package com.notsecurebank.servlet;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

/**
 * This servlet allows this application to use 'static' pages from
 * the .NET version of the application 'AS IS' by converting requests
 * for .aspx files into requests for .jsp files with the same name
 * Servlet implementation class RedirectServlet
 */
public class RedirectServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger LOG = LogManager.getLogger(RedirectServlet.class);

    public RedirectServlet() {
        super();
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        LOG.info("doGet");

        String url = request.getServletPath().toString();
        if (url.endsWith(".aspx")) {
            url = url.substring(0, url.lastIndexOf(".aspx")) + ".jsp";
        }
        RequestDispatcher dispatcher = request.getRequestDispatcher(url);
        dispatcher.forward(request, response);
    }
}
