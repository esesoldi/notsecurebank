<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
 
<jsp:include page="/header.jspf"/>

<div id="wrapper" style="width: 99%;">
	<jsp:include page="membertoc.jspf"/>
    <td valign="top" colspan="3" class="bb">
    	<%@page import="com.notsecurebank.util.ServletUtil"%>
		<div class="fl" style="width: 99%;">
			<h1>Gold Visa Application</h1>
			<% 
			   com.notsecurebank.model.User user = (com.notsecurebank.model.User)request.getSession().getAttribute("user");
               if (ServletUtil.isPreApprovedForGoldVisa(request) && !user.hasGoldVisaDelivery()) { 
            %>
			<span><p><b>No application is needed. </b>To approve your new $10000 Gold Visa<br />with an 7.9% APR simply enter your password below.</p><form method="post" name="Credit" action="ccApply"><table border=0><tr><td>Password:</td><td><input type="password" name="passwd"></td></tr><tr><td></td><td><input type="submit" name="Submit" value="Submit"></td></tr></table></form></span>
			<% } else { %>
			<p>Sorry, you can't perform this operation.</p>
			<% } %>
		</div>
    </td>	
</div>
<jsp:include page="/footer.jspf"/>   
