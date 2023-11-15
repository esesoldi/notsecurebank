<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>  
    
<jsp:include page="/header.jspf"/>

<div id="wrapper" style="width: 99%;">
	<jsp:include page="membertoc.jspf"/>
    <td valign="top" colspan="3" class="bb">
		<div class="fl" style="width: 99%;">
		
		<h1>Gold Visa Application</h1>
		<% if ("ok".equals(request.getAttribute("gold_visa_delivery"))) { %>
		<span id="_ctl0__ctl0_Content_Main_lblMessage">Your new Gold VISA with a $10000 and 7.9% APR will be sent in the mail.</span>
		<% } else { %>
		<p>Sorry, you can't perform this operation.</p>
		<% } %>
		</div>
	</td>	
</div>

<jsp:include page="/footer.jspf"/>  