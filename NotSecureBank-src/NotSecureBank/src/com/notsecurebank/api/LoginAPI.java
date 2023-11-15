package com.notsecurebank.api;

import java.security.InvalidParameterException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.wink.json4j.JSONException;
import org.apache.wink.json4j.JSONObject;

import com.notsecurebank.util.DBUtil;
import com.notsecurebank.util.ServletUtil;

@Path("login")
public class LoginAPI extends NotSecureBankAPI {

    private static final Logger LOG = LogManager.getLogger(LoginAPI.class);

    @GET
    @Produces("application/json")
    public Response checkLogin(@Context HttpServletRequest request) throws JSONException {
        LOG.info("checkLogin");

        JSONObject myJson = new JSONObject();
        if (ServletUtil.isLoggedin(request)) {
            myJson.put("loggedin", "true");
            myJson.put("user", ServletUtil.getUser(request).getUsername());
            return Response.status(200).entity(myJson.toString()).build();
        } else {
            myJson.put("loggedin", "false");
            return Response.status(200).entity(myJson.toString()).build();
        }
    }

    @POST
    @Produces("application/json")
    public Response login(String bodyJSON, @Context HttpServletRequest request) throws JSONException {
        LOG.info("login");

        HttpSession session = request.getSession(true);

        JSONObject myJson = new JSONObject();
        try {
            myJson = new JSONObject(bodyJSON);
        } catch (Exception e) {
            LOG.error(e.toString());
            myJson.clear();
            myJson.put("error", "body is not JSON");
            return Response.status(400).entity(myJson.toString()).build();
        }

        // Check username and password parameters are there
        if (!myJson.containsKey("username") && myJson.containsKey("password")) {
            LOG.error("Username/password is missing.");
            myJson.clear();
            myJson.put("error", "username or password parameter missing");
            return Response.status(400).entity(myJson.toString()).build();
        }

        String username, password;
        username = myJson.get("username").toString().trim().toLowerCase();
        password = myJson.get("password").toString().trim();

        myJson.clear();

        try {
            if (!DBUtil.isValidApiUser(username, password)) {
                throw new InvalidParameterException("We're sorry, but this username or password was not found in our system.");
            }
        } catch (Exception e) {
            LOG.error(e.toString());
            myJson.put("error", e.getLocalizedMessage());
            return Response.status(400).entity(myJson.toString()).build();
        }

        try {
            Cookie accountCookie = ServletUtil.establishSession(username, session);
            javax.ws.rs.core.Cookie someCookie = new javax.ws.rs.core.Cookie(ServletUtil.NOT_SECURE_BANK_COOKIE, accountCookie.getValue());
            NewCookie myCookie = new NewCookie(someCookie);
            myJson.put("success", username + " is now logged in");
            return Response.status(200).entity(myJson.toString()).cookie(myCookie).build();
        } catch (Exception ex) {
            LOG.error(ex.toString());
            myJson.put("error", "Unexpected error occured. Please try again");
            return Response.status(500).entity(myJson.toString()).build();
        }
    }
}
