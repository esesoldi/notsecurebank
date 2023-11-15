<%@page import="com.notsecurebank.model.Feedback"%>
<%@page import="java.util.HashMap"%>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>

    <%@page import="com.notsecurebank.util.ServletUtil" errorPage="notfound.jsp"%>
    <%@page import="org.apache.commons.lang.StringEscapeUtils" errorPage="notfound.jsp"%>


<jsp:include page="header.jspf"/>

<div id="wrapper" style="width: 99%;">
	<jsp:include page="toc.jspf"/>
    <td valign="top" colspan="3" class="bb">
    
    
		
		<div class="fl" style="width: 99%;">
		
		 <h1>Thank You</h1>
		 
		 <p>Thank you for your comments<%= (request.getAttribute("message_feedback")!=null)?", "+request.getAttribute("message_feedback"):"" %>.  They will be reviewed by our Customer Service staff and given the full attention that they deserve. 
		 <% String email = (String) request.getParameter("email_addr"); 
		 	boolean regExMatch = email!=null && email.matches(ServletUtil.EMAIL_REGEXP);
		 	if (email != null && email.trim().length() != 0 && regExMatch) {%> 
			 Our reply will be sent to your email: <%= ServletUtil.sanitizeHtmlWithRegex(email.toLowerCase()) %>
		<% } else {%>
			However, the email you gave is incorrect (<%=ServletUtil.sanitizeHtmlWithRegex(email.toLowerCase()) %>) and you will not receive a response.
		<% }%>
		</p>
		<br><br>
		<h3>Details of your feedback submission</h3>
		<p>
		<% 
		long feedbackId = -1;
		Object feedbackIdObj = request.getAttribute("feedback_id");
		if (feedbackIdObj != null && feedbackIdObj instanceof String) {
			feedbackId = Long.parseLong((String)feedbackIdObj);
		}
		
		Feedback feedbackDetails = ServletUtil.getFeedback(feedbackId);
		
		if (feedbackDetails != null){
			
		%>
			<table border=0>
			  <tr>
			    <td align=right>Your Name:</td>
			    <td valign=top><%=feedbackDetails.getName() %></td>
			  </tr>
			  <tr>
			    <td align=right>Your Email Address:</td>
			    <td valign=top><%=feedbackDetails.getEmail() %></td>
			  </tr>
			  <tr>
			    <td align=right>Subject:</td>
			    <td valign=top><%=feedbackDetails.getSubject() %></td>
			  </tr>
			  <tr>
			    <td align=right valign=top>Question/Comment:</td>
			    <td><%=feedbackDetails.getMessage()%></td>
			  </tr>
			</table>
		<% } %>
		</p>
		</div>
    </td>	
</div>

<jsp:include page="footer.jspf"/>