<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
    
<jsp:include page="/header.jspf"/>

<div id="wrapper" style="width: 99%;">
	<jsp:include page="membertoc.jspf"/>
    <td valign="top" colspan="3" class="bb">
		<div class="fl" style="width: 99%;">
		
		<%
			String content = request.getParameter("content");
			if (content != null && !content.equalsIgnoreCase("customize.jsp")){
				if (content.startsWith("http://") || content.startsWith("https://")){
					response.sendRedirect(content);
				}
			}
		%>
		
		<h1>Customize Site Language</h1>
		
		<form method="post">
		  <p>
		  Current Language: <%=(request.getParameter("lang")==null)?"":request.getParameter("lang")%>
		  </p>
		
		  <p>
		  You can change the language setting by choosing:
		  </p>
		  <p>
		  <a id="HyperLink1" href="./customize.jsp?content=customize.jsp&lang=international">International</a>
		  <a id="HyperLink2" href="./customize.jsp?content=customize.jsp&lang=english">English</a>
		  </p>
		</form>
		
		</div>
    </td>	
</div>

<jsp:include page="/footer.jspf"/>  