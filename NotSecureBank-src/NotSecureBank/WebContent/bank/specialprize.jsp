<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>  
    
<jsp:include page="/header.jspf"/>

<div id="wrapper" style="width: 99%;">
	<jsp:include page="membertoc.jspf"/>
    <td valign="top" colspan="3" class="bb">
		<div class="fl" style="width: 99%;">
		
		<h1>Special Prize</h1>
		<p><%= request.getAttribute("message_special_prize") == null ? "You can't perform this operation." : request.getAttribute("message_special_prize") %></p>
		</div>
	</td>	
</div>

<jsp:include page="/footer.jspf"/>  