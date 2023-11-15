<%@page import="org.apache.commons.lang3.StringEscapeUtils"%>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
    
<jsp:include page="header.jspf"/>

<div id="wrapper" style="width: 99%;">
	<jsp:include page="toc.jspf"/>
    <td valign="top" colspan="3" class="bb">
		<%@page isErrorPage="true" %>
		<div class="fl" style="width: 99%;">
		<h1>An Error Has Occurred</h1>
		
		<p><% 
		if (exception != null) {
			String message = StringEscapeUtils.escapeHtml4(exception.getMessage());
			out.println(message);
			System.out.println(exception.getMessage());
		} else {
			out.println("An error has occurred.");
		}
		%></p>

		</div>
	</td>
</div>
<jsp:include page="footer.jspf"/>