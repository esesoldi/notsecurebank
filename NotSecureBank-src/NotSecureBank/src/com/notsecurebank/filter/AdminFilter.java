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
import com.notsecurebank.model.User.Role;
import com.notsecurebank.util.ServletUtil;

public class AdminFilter implements Filter {

    private static final Logger LOG = LogManager.getLogger(AdminFilter.class);

    public AdminFilter() {
        super();
    }

    public void init(FilterConfig arg0) throws ServletException {
    }

    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {
        LOG.info("doFilter");

        if (req instanceof HttpServletRequest) {

            HttpServletRequest request = (HttpServletRequest) req;
            Object admObj = request.getSession().getAttribute(ServletUtil.SESSION_ATTR_ADMIN_KEY);
            Object user = request.getSession().getAttribute(ServletUtil.SESSION_ATTR_USER);

            if ((user != null && ((User) user).getRole() == Role.Admin) || (admObj != null && admObj instanceof String && ((String) admObj).equals(ServletUtil.SESSION_ATTR_ADMIN_VALUE))) {
                chain.doFilter(req, resp);
                return;
            } else if (request.getRequestURL().toString().endsWith("/admin/login.jsp") || request.getRequestURL().toString().endsWith("/admin/doAdminLogin")) {
                LOG.info("To admin login.");
                chain.doFilter(req, resp);
                return;
            } else if (user == null || !(user instanceof User)) {
                LOG.info("Redirect to login page.");
                ((HttpServletResponse) resp).sendRedirect(request.getContextPath() + "/login.jsp");
                return;
            } else {
                LOG.info("Redirect to main bank page.");
                ((HttpServletResponse) resp).sendRedirect(request.getContextPath() + "/bank/main.jsp");
                return;
            }
        }
    }

    public void destroy() {
    }

}