package com.notsecurebank.servlet;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringEscapeUtils;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

public class FindLocationServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger LOG = LogManager.getLogger(FindLocationServlet.class);

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        LOG.info("doPost");

        String locationType = request.getParameter("locationType");
        String street = request.getParameter("street");
        String city = request.getParameter("city");
        String stateProvince = request.getParameter("stateProvince");
        String locationsFileName = request.getParameter("locations");

        if (locationsFileName == null || locationsFileName.trim().length() == 0 || locationType == null || locationType.trim().length() == 0 || city == null || city.trim().length() == 0 || stateProvince == null || stateProvince.trim().length() == 0) {
            // Check for mandatory input.
            request.setAttribute("response", "mandatory_input");
            request.setAttribute("locations", null);
            LOG.error("Missing mandatory input.");

        } else {
            String filePath = request.getSession().getServletContext().getRealPath("/util") + File.separator + locationsFileName;
            File locationsFile = new File(filePath);
            LOG.debug("File path is '" + filePath + "'.");

            if (locationsFile != null && locationsFile.canRead() && locationsFile.isFile() && locationsFile.getCanonicalPath().contains("notsecurebank")) {

                List<String> allList = new ArrayList<String>();
                List<String> foundList = new ArrayList<String>();
                BufferedReader br = null;
                FileReader fr = null;

                try {

                    String sCurrentLine;
                    br = new BufferedReader(new FileReader(locationsFile));
                    LOG.debug("Start searching.");

                    while ((sCurrentLine = br.readLine()) != null) {
                        if (isSearchedOne(sCurrentLine.trim(), locationType.trim(), city.trim(), stateProvince.trim(), street)) {
                            foundList.add(StringEscapeUtils.escapeHtml(sCurrentLine.trim()));
                        }
                        allList.add(StringEscapeUtils.escapeHtml(sCurrentLine.trim()));
                    }

                    if (foundList.size() > 0) {
                        request.setAttribute("response", "found_locations");
                        request.setAttribute("locations", foundList);
                    } else {
                        request.setAttribute("response", "not_found_locations");
                        request.setAttribute("locations", allList);
                    }

                } catch (Exception e) {
                    request.setAttribute("response", "unexpected_error");
                    request.setAttribute("locations", null);
                    LOG.error(e.toString());
                } finally {
                    try {
                        if (br != null) {
                            br.close();
                        }
                        if (fr != null) {
                            fr.close();
                        }
                    } catch (Exception ex) {
                        request.setAttribute("response", "unexpected_error");
                        request.setAttribute("locations", null);
                        LOG.error(ex.toString());
                    }
                }

            } else {
                request.setAttribute("response", "unexpected_error");
                request.setAttribute("locations", null);
                LOG.error("Pointed file is null, not a file, non readable or out of application context.");
            }
        }

        RequestDispatcher dispatcher = request.getRequestDispatcher("locations.jsp");
        dispatcher.forward(request, response);
    }

    private boolean isSearchedOne(String location, String targetLocationType, String targetCity, String targetStateProvince, String targetStreet) {
        LOG.debug("isSearchedOne('" + location + "', '" + targetLocationType + "', '" + targetCity + "', '" + targetStateProvince + "', '" + targetStreet + "')");

        boolean out = false;

        String[] locationArray = location.split(":");
        if (locationArray != null && locationArray.length == 2 && locationArray[0] != null && locationArray[1] != null && targetLocationType.equals(locationArray[0].trim())) {
            LOG.debug("locationArray[0] = " + locationArray[0].trim());
            LOG.debug("locationArray[1] = " + locationArray[1].trim());

            String[] position = locationArray[1].trim().split(",");
            if (position != null && position.length == 3 && position[0] != null && position[1] != null && position[2] != null && targetCity.toLowerCase().equals(position[1].trim().toLowerCase()) && position[2].trim().startsWith(targetStateProvince.trim())) {
                LOG.debug("position[0] = " + position[0].trim());
                LOG.debug("position[1] = " + position[1].trim());
                LOG.debug("position[2] = " + position[2].trim());

                if (targetStreet != null && targetStreet.trim().length() > 0) {
                    if (position[0].trim().toLowerCase().contains(targetStreet.trim().toLowerCase())) {
                        out = true;
                    }
                } else {
                    out = true;
                }
            }

        }

        return out;
    }
}
