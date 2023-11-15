package com.notsecurebank.api;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import com.notsecurebank.util.ServletUtil;

@Path("/logout")
public class LogoutAPI extends NotSecureBankAPI {

    private static final Logger LOG = LogManager.getLogger(LogoutAPI.class);

    @GET
    @Produces("application/json")
    public Response doLogOut(@Context HttpServletRequest request) {
        LOG.info("doLogOut");

        try {
            request.getSession().removeAttribute(ServletUtil.SESSION_ATTR_USER); // Removing user.
            request.getSession().removeAttribute(ServletUtil.SESSION_ATTR_ADMIN_KEY); // Removing admin.
            String response = "{\"LoggedOut\" : \"True\"}";
            return Response.status(200).entity(response).build();
        } catch (Exception e) {
            LOG.error(e);
            String response = "{\"Error \": \"Unknown error encountered\"}";
            return Response.status(500).entity(response).build();
        }
    }
}
