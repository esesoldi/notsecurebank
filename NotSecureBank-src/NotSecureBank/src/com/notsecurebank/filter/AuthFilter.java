package com.notsecurebank.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import com.notsecurebank.model.User;
import com.notsecurebank.util.ServletUtil;

public class AuthFilter implements Filter {

    private static final Logger LOG = LogManager.getLogger(AuthFilter.class);

    public AuthFilter() {
        super();
    }

    public void init(FilterConfig arg0) throws ServletException {
    }

    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {
        if (req instanceof HttpServletRequest) {
            HttpServletRequest request = (HttpServletRequest) req;
            Object user = request.getSession().getAttribute(ServletUtil.SESSION_ATTR_USER);
            if (user == null || !(user instanceof User)) {
                LOG.info("Redirect to login page.");
                ((HttpServletResponse) resp).sendRedirect(request.getContextPath() + "/login.jsp");
                return;
            } else {
                chain.doFilter(req, resp);
            }
        }
    }

    public void destroy() {
    }

}