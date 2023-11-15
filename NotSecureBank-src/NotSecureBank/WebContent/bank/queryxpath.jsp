<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
    
<jsp:include page="/header.jspf"/>

<div id="wrapper" style="width: 99%;">
	<jsp:include page="membertoc.jspf"/>
    <td valign="top" colspan="3" class="bb">
		<%@page import="com.notsecurebank.util.ServletUtil"%>
		<div class="fl" style="width: 99%;">
			<h1>Search News Articles</h1>
			<form id="QueryXpath" method="get" action="<%=request.getRequestURL()%>">
			  Search our news articles database
			  <br /><br />
				<input type="hidden" id=content" name="content" value="queryxpath.jsp"/>
				<input type="text" id="query" name="query" width=450 value="<%=(request.getParameter("query")==null)?"Enter title (e.g. Reply)":request.getParameter("query")%>"/>
				<input type="submit" width=75 id="Button1" value="Query">
			  <br /><br />
			<%
				if (request.getParameter("query") != null) {
				String[] results = ServletUtil.searchArticles(request.getParameter("query"), request.getSession().getServletContext().getRealPath("/pr/Docs.xml"));
				if (results == null)
					out.println("News title not found, try again");
				else {
					out.println("Found news title:<br/>");
					for(String result:results)
				out.println(result+"<br/>");
				}
			}
			%>
			
			</form>
		</div>    
    </td>	
</div>

<jsp:include page="/footer.jspf"/>  