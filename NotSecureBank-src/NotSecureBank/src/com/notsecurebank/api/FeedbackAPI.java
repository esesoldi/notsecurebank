package com.notsecurebank.api;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.wink.json4j.JSONException;
import org.apache.wink.json4j.JSONObject;

import com.notsecurebank.model.Feedback;
import com.notsecurebank.util.OperationsUtil;
import com.notsecurebank.util.ServletUtil;

@Path("/feedback")
public class FeedbackAPI extends NotSecureBankAPI {

    private static final Logger LOG = LogManager.getLogger(FeedbackAPI.class);

    @POST
    @Path("/submit")
    @Produces("application/json")
    public Response sendFeedback(String bodyJSON, @Context HttpServletRequest request) throws JSONException {
        LOG.info("sendFeedback");

        String response = "";
        JSONObject myJson = new JSONObject();
        try {
            myJson = new JSONObject(bodyJSON);
        } catch (Exception e) {
            LOG.error(e.toString());
            return Response.status(400).entity("{Error: Request is not in JSON format}").build();
        }

        // Get the feedback details
        String name;
        String email;
        String subject;
        String comments;

        try {
            name = (String) myJson.get("name");
            email = (String) myJson.get("email");
            subject = (String) myJson.get("subject");
            comments = (String) myJson.get("message");
        } catch (JSONException e) {
            LOG.error(e.toString());
            return Response.status(400).entity("{\"Error\": \"Body does not contain all the correct attributes\"}").build();
        }

        String feedbackId = OperationsUtil.sendFeedback(name, email, subject, comments);

        if (feedbackId != null) {
            response = "{\"status\":\"Thank you!\",\"feedbackId\":\"" + feedbackId + "\"}";
            try {
                myJson = new JSONObject(response);
                return Response.status(200).entity(myJson.toString()).build();
            } catch (JSONException e) {
                LOG.error(e.toString());
                return Response.status(500).entity("{\"Error\":\"Unknown internal error:" + e.getLocalizedMessage() + "\"}").build();
            }
        } else {
            myJson = new JSONObject();
            myJson.put("name", name);
            myJson.put("email", email);
            myJson.put("subject", subject);
            myJson.put("comments", comments);
            return Response.status(200).entity(myJson.toString()).build();
        }
    }

    @GET
    @Path("/{feedbackId}")
    @Produces("application/json")
    public Response getFeedback(@PathParam("feedbackId") String feedbackId, @Context HttpServletRequest request) {
        LOG.info("getFeedback");

        Feedback feedbackDetails = ServletUtil.getFeedback(Long.parseLong(feedbackId));
        String response = "";
        response += "{\"name\":\"" + feedbackDetails.getName() + "\"," + "\n\"email\":\"" + feedbackDetails.getEmail() + "\"," + "\n\"subject\":\"" + feedbackDetails.getSubject() + "\"," + "\n\"message\":\"" + feedbackDetails.getMessage() + "\"}";

        return Response.status(200).entity(response).build();

    }

}
