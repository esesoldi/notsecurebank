package com.notsecurebank.servlet;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Random;

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

public class SpecialPrizeServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger LOG = LogManager.getLogger(SpecialPrizeServlet.class);

    private static String[] prizes = { "USB charger", "USB Flash Drive", "Mouse", "MP3 Player", "Wallet", "Smartphone", "Laptop", "3 Books", "+100$ Bonus", "Car", "Keychain", "+50$ Bonus", "Backpack", "Sunglasses", "+150$ Bonus" };

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        LOG.info("doPost");

        if (!ServletUtil.isLoggedin(request)) {
            response.sendRedirect("login.jsp");
            return;
        }

        User user = (User) request.getSession().getAttribute(ServletUtil.SESSION_ATTR_USER);
        String username = user.getUsername();

        String messageSpecialPrize = null;
        String passedSpecialPrizeCode = request.getParameter("specialPrizeCode");
        String expectedSpecialPrizeCode = (String) request.getSession().getAttribute("specialPrizeCode");

        if (passedSpecialPrizeCode != null && passedSpecialPrizeCode.equals(expectedSpecialPrizeCode)) {
            try {

                String randomPrize = randomPrize();
                DBUtil.addSpecialPrize(username, passedSpecialPrizeCode, randomPrize);
                messageSpecialPrize = "Congratulations! Your special prize is: <strong>" + randomPrize + "</strong>. You will be contacted for further information.";

            } catch (Exception e) {
                messageSpecialPrize = "Unexpected error.";
            }

        } else {
            messageSpecialPrize = "You can't perform this operation.";
        }

        request.setAttribute("message_special_prize", messageSpecialPrize);
        RequestDispatcher dispatcher = request.getRequestDispatcher("specialprize.jsp");
        dispatcher.forward(request, response);

    }

    private String randomPrize() {
        Random random = new SecureRandom();
        int i = random.nextInt(prizes.length);
        return prizes[i];
    }
}
