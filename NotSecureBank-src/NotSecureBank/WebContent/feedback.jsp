<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
    
<jsp:include page="header.jspf"/>

<div id="wrapper" style="width: 99%;">
	<jsp:include page="toc.jspf"/>
    <td valign="top" colspan="3" class="bb">
		<%@page import="com.notsecurebank.model.User"%>

		<%User user = null;
		try {
		 user = (User)request.getSession().getAttribute("user"); 
		} catch (Exception e) { /* do nothing */ }%>
		
		<div class="fl" style="width: 99%;">
		
		<h1>Feedback</h1>
		
		<p>Our Frequently Asked Questions area will help you with many of your inquiries.<br />
		If you can't find your question, return to this page and use the e-mail form below.</p>
		
		<p><b>IMPORTANT!</b> This feedback facility is not secure.  Please do not send any <br />
		account information in a message sent from here.</p>
		
		<form name="cmt" method="post" action="sendFeedback">
		
		<table border=0>
		  <tr>
		    <td align=right>To:</td>
		    <td valign=top><b>Online Banking</b> </td>
		  </tr>
		  <tr>
		    <td align=right>Your Name:</td>
		    <td valign=top><input name="name" size=25 type=text value = "<%= ((user != null && user.getFirstName() != null)?user.getFirstName()+" ":"") + ((user != null && user.getLastName() != null)?user.getLastName():"") %>"></td>
		  </tr>
		  <tr>
		    <td align=right>Your Email Address:</td>
		    <td valign=top><input name="email_addr" type=text size=25></td>
		  </tr>
		  <tr>
		    <td align=right>Subject:</td>
		    <td valign=top><input name="subject" size=25></td>
		  </tr>
		  <tr>
		    <td align=right valign=top>Question/Comment:</td>
		    <td><textarea cols=65 name="comments" rows=8 wrap=PHYSICAL align="top"></textarea></td>
		  </tr>
		  <tr>
		    <td>&nbsp;</td>
		    <td><input type=submit value=" Submit " name="submit">&nbsp;<input type=reset value=" Clear Form " name="reset"></td>
		  </tr>
		</table>
		</form>
		
		<br /><br />
		
		</div>
    </td>
	
</div>

<jsp:include page="footer.jspf"/>