package com.notsecurebank.api;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.wink.json4j.JSONException;
import org.apache.wink.json4j.JSONObject;

import com.notsecurebank.util.DBUtil;
import com.notsecurebank.util.ServletUtil;

@Path("/admin")
public class AdminAPI extends NotSecureBankAPI {

    private static final Logger LOG = LogManager.getLogger(AdminAPI.class);

    @POST
    @Path("/changePassword")
    @Produces("application/json")
    public Response changePassword(String bodyJSON, @Context HttpServletRequest request) throws IOException {
        LOG.info("changePassword");

        JSONObject bodyJson = new JSONObject();

        // Checking if user is logged in
        if (!ServletUtil.isLoggedin(request)) {
            String response = "{\"loggedIn\" : \"false\"}";
            return Response.status(400).entity(response).build();
        }

        // Convert request to JSON
        String username;
        String password1;
        String password2;
        try {
            bodyJson = new JSONObject(bodyJSON);

            // Parse the body for the required parameters
            username = bodyJson.get("username").toString();
            password1 = bodyJson.get("password1").toString();
            password2 = bodyJson.get("password2").toString();
        } catch (JSONException e) {
            LOG.error(e.toString());
            return Response.status(500).entity("{\"Error\": \"Request is not in JSON format\"}").build();
        }

        // Try to change the password
        if (username == null || username.trim().length() == 0 || password1 == null || password1.trim().length() == 0 || password2 == null || password2.trim().length() == 0) {
            LOG.error("Passed data null or empty for changePassword method.");
            return Response.status(500).entity("{\"error\":\"An error has occurred. Please try again later.\"}").build();
        }

        if (!password1.equals(password2)) {
            LOG.error("Entered passwords did not match for changePassword method.");
            return Response.status(500).entity("{\"error\":\"Entered passwords did not match.\"}").build();
        }

        String error = DBUtil.changePassword(username, password1);
        if (error != null)
            return Response.status(500).entity("{\"error\":\"" + error + "\"}").build();

        return Response.status(200).entity("{\"success\":\"Requested operation has completed successfully.\"}").build();
    }

    @POST
    @Path("/addUser")
    @Produces("application/json")
    public Response addUser(String bodyJSON, @Context HttpServletRequest request) throws IOException {
        LOG.info("addUser");

        JSONObject bodyJson = new JSONObject();

        // Checking if user is logged in

        if (!ServletUtil.isLoggedin(request)) {
            String response = "{\"loggedIn\" : \"false\"}";
            return Response.status(400).entity(response).build();
        }

        String firstname;
        String lastname;
        String username;
        String email;
        String password1;
        String password2;

        // Convert request to JSON
        try {
            bodyJson = new JSONObject(bodyJSON);
            // Parse the request for the required parameters
            firstname = bodyJson.get("firstname").toString();
            lastname = bodyJson.get("lastname").toString();
            username = bodyJson.get("username").toString();
            email = bodyJson.get("email").toString();
            password1 = bodyJson.get("password1").toString();
            password2 = bodyJson.get("password2").toString();
        } catch (JSONException e) {
            LOG.error(e.toString());
            return Response.status(500).entity("{\"Error\": \"Request is not in JSON format\"}").build();
        }

        if (firstname == null || firstname.trim().length() == 0 || lastname == null || lastname.trim().length() == 0 || username == null || username.trim().length() == 0 || email == null || email.trim().length() == 0 || password1 == null || password1.trim().length() == 0 || password2 == null || password2.trim().length() == 0) {
            LOG.error("Inserted data null or empty for addUser method.");
            return Response.status(500).entity("{\"error\":\"An error has occurred. Please try again later.\"}").build();
        }

        if (!password1.equals(password2)) {
            LOG.error("Entered passwords did not match for addUser method.");
            return Response.status(500).entity("{\"error\":\"Entered passwords did not match.\"}").build();
        }

        if (!ServletUtil.isValidEmail(email)) {
            LOG.error("Entered email is not valid.");
            return Response.status(500).entity("{\"error\":\"Entered email is not valid.\"}").build();
        }

        String error = DBUtil.addUser(username, password1, firstname, lastname, email);
        if (error != null)
            return Response.status(500).entity("{\"error\":\"" + error + "\"}").build();

        return Response.status(200).entity("{\"success\":\"Requested operation has completed successfully.\"}").build();
    }

}
