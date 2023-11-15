<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
    
<jsp:include page="/header.jspf"/>

<div id="wrapper" style="width: 99%;">
	<jsp:include page="/toc.jspf"/>
	<td valign="top" colspan="3" class="bb">
		<h1>Administration Login</h1>
		
		<form id="Default" method="post" action="doAdminLogin">
		  <p>
		    <strong>Enter the administrative username:</strong><br />
		    <input id="username" name="username" type="text" /><br /><br />
		    <strong>Enter the administrative password:</strong><br />
		    <input id="password" name="password" type="password" /><br /><br />
		    <input type="submit" name="btnSubmit" value="Login">
		  </p>
		<p><span id="_ctl0__ctl0_Content_Main_message" style="color:#FF0066;font-size:12pt;font-weight:bold;">
			<%
			java.lang.String error = (String)request.getAttribute("loginError");
			
			if (error != null && error.trim().length() > 0){
				request.getSession().removeAttribute("loginError");
				out.print(error);
			}
			%>
		</span></p>
		</form>
		
		<script>
		window.onload = document.forms[1].elements[1].focus();
		</script>
	</td>
</div>

<jsp:include page="/footer.jspf"/>