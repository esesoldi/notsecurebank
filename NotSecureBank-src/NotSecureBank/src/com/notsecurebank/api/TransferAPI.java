package com.notsecurebank.api;

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

import com.notsecurebank.util.OperationsUtil;

@Path("transfer")
public class TransferAPI extends NotSecureBankAPI {

    private static final Logger LOG = LogManager.getLogger(TransferAPI.class);

    @POST
    @Produces("application/json")
    public Response transfer(String bodyJSON, @Context HttpServletRequest request) {
        LOG.info("transfer");

        JSONObject myJson = new JSONObject();
        Long creditActId;
        String fromAccount;
        double amount;
        String message;

        try {
            myJson = new JSONObject(bodyJSON);
            // Get the transaction parameters
            creditActId = Long.parseLong(myJson.get("toAccount").toString());
            fromAccount = myJson.get("fromAccount").toString();
            amount = Double.parseDouble(myJson.get("transferAmount").toString());
            message = OperationsUtil.doTransfer(request, creditActId, fromAccount, amount);
        } catch (JSONException e) {
            LOG.error(e.toString());
            return Response.status(500).entity("{\"Error\": \"Request is not in JSON format\"}").build();
        }

        if (message.startsWith("ERROR")) {
            return Response.status(500).entity("\"error\":\"" + message + "\"}").build();
        }

        return Response.status(200).entity("{\"success\":\"" + message + "\"}").build();
    }
}
