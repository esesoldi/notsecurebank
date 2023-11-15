<%@page import="java.util.ArrayList"%>
<%@page import="com.notsecurebank.model.Feedback"%>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
  
<jsp:include page="/header.jspf"/>

<div id="wrapper" style="width: 99%;">
	<jsp:include page="/bank/membertoc.jspf"/>
	<td valign="top" colspan="3" class="bb">
		<%@page import="com.notsecurebank.util.ServletUtil"%>
		
		<br><br>
		<h1>Customer feedback submissions</h1>
		<p>
		<% 
		
		ArrayList<Feedback> feedbackDetails = ServletUtil.getAllFeedback();
		
		for (int i=0; i<feedbackDetails.size();i++){
			
		%>
			<table border=0>
			  <tr>
			    <td align=right>Feedback ID:</td>
			    <td valign=top><%=feedbackDetails.get(i).getFeedbackID() %></td>
			  </tr>
			  <tr>
			    <td align=right>Customer Name:</td>
			    <td valign=top><%=feedbackDetails.get(i).getName() %></td>
			  </tr>
			  <tr>
			    <td align=right>Customer Email Address:</td>
			    <td valign=top><%=feedbackDetails.get(i).getEmail() %></td>
			  </tr>
			  <tr>
			    <td align=right>Customer Subject:</td>
			    <td valign=top><%=feedbackDetails.get(i).getSubject() %></td>
			  </tr>
			  <tr>
			    <td align=right valign=top>Customer Question/Comment:</td>
			    <td><%=feedbackDetails.get(i).getMessage()%></td>
			  </tr>
			</table>
			<hr>
		<% } %>
		</p>
		</div>
    </td>
</div>

<jsp:include page="/footer.jspf"/>		