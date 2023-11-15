<%@page import="java.io.BufferedReader"%>
<%@page import="java.io.InputStream"%>
<%@page import="java.io.InputStreamReader"%>
<%@page import="com.notsecurebank.util.ServletUtil"%>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
    
<jsp:include page="header.jspf"/>

<div id="wrapper" style="width: 99%;">
	<jsp:include page="toc.jspf"/>
    <td valign="top" colspan="3" class="bb">
		<%		
		java.lang.String content = request.getParameter("content");
		if (content == null)
			content = "default.htm";
		else
			content = request.getParameter("content");
			content = "static/"+content;
		%>
		
		<%  try { %>
			<jsp:include page="<%= content %>"/>
		<%  } catch (Exception e) { %>
			<p>Failed due to <%= ServletUtil.sanitizeHtmlWithRegex(e.getLocalizedMessage()) %></p>
 		<% } %>
    </td>
	
</div>

<jsp:include page="footer.jspf"/>