<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
	pageEncoding="ISO-8859-1"%>

<jsp:include page="header.jspf" />

<div id="wrapper" style="width: 99%;">
	<jsp:include page="toc.jspf" />
	<td valign="top" colspan="3" class="bb">
	<%@page import="java.util.List"%>

		<div class="fl" style="width: 67%;">

			<h1>Locations</h1>

			<p>
				Find ATM or Branch Office.<br /> An asterisk (*) indicates a
				required field.
			</p>
			<form action="doFindLocation" method="post" name="findLocation"
				id="findLocation">
				<table border=0>
					<tr>
						<td class=standard-font><input type="radio"
							name="locationType" value="BANKINGCENTERS" id="BANKINGCENTERS">&nbsp;<LABEL
							FOR="BANKINGCENTERS">Branch Office</LABEL><BR> <input
							type="radio" name="locationType" value="ATM" checked="checked"
							id="ATM">&nbsp;<LABEL FOR="ATM">ATMs</LABEL><br> <input
							type="radio" name="locationType" value="TALKINGATM"
							id="TALKINGATM">&nbsp;<LABEL FOR="TALKINGATM">Talking
								ATMs</LABEL><br></td>
					</tr>
					<tr>
						<td>Street Address or Intersection</td>
						<td width="10">&nbsp;</td>
						<td><input type="text" name="street" maxlength="75" size="25"
							value="" class="white" id="STREET"></td>
					</tr>
					<tr>
						<td>City*</td>
						<td width="10">&nbsp;</td>
						<td><input type="text" name="city" maxlength="75" size="20"
							value="" id="CITY"></td>
					</tr>
					<tr>
						<td>State*</td>
						<td width="10">&nbsp;</td>
						<td><select name="stateProvince" size="1" id="STATE_PROV"><option
									value="">select state</option>
								<option value="AL">Alabama</option>
								<option value="AK">Alaska</option>
								<option value="AZ">Arizona</option>
								<option value="AR">Arkansas</option>
								<option value="CA">California</option>
								<option value="CO">Colorado</option>
								<option value="CT">Connecticut</option>
								<option value="DC">District of Columbia</option>
								<option value="DE">Delaware</option>
								<option value="FL">Florida</option>
								<option value="GA">Georgia</option>
								<option value="HI">Hawaii</option>
								<option value="ID">Idaho</option>
								<option value="IL">Illinois</option>
								<option value="IN">Indiana</option>
								<option value="IA">Iowa</option>
								<option value="KS">Kansas</option>
								<option value="KY">Kentucky</option>
								<option value="LA">Louisiana</option>
								<option value="ME">Maine</option>
								<option value="MD">Maryland</option>
								<option value="MA" selected="selected">Massachusetts</option>
								<option value="MI">Michigan</option>
								<option value="MN">Minnesota</option>
								<option value="MS">Mississippi</option>
								<option value="MO">Missouri</option>
								<option value="MT">Montana</option>
								<option value="NE">Nebraska</option>
								<option value="NV">Nevada</option>
								<option value="NH">New Hampshire</option>
								<option value="NJ">New Jersey</option>
								<option value="NM">New Mexico</option>
								<option value="NY">New York</option>
								<option value="NC">North Carolina</option>
								<option value="ND">North Dakota</option>
								<option value="OH">Ohio</option>
								<option value="OK">Oklahoma</option>
								<option value="OR">Oregon</option>
								<option value="PA">Pennsylvania</option>
								<option value="RI">Rhode Island</option>
								<option value="SC">South Carolina</option>
								<option value="SD">South Dakota</option>
								<option value="TN">Tennessee</option>
								<option value="TX">Texas</option>
								<option value="UT">Utah</option>
								<option value="VT">Vermont</option>
								<option value="VA">Virginia</option>
								<option value="WA">Washington</option>
								<option value="WV">West Virginia</option>
								<option value="WI">Wisconsin</option>
								<option value="WY">Wyoming</option></select></td>
					</tr>
					<tr>
					<td><input type="hidden" name="locations" value="locations.dat" /></td>
					<td></td>
					<td><input type="submit" name="btnSubmit" value="Find" /></td>
					</tr>
				</table>	
			</form>

			<% if("mandatory_input".equals(request.getAttribute("response"))) { %>
				<p><span style="color:#FF0066;font-weight:bold;">Mandatory parameters are missing.</span></p>
			<% } else if("found_locations".equals(request.getAttribute("response"))) { %>
				<p>Found following location(s):</p>
			<% } else if("not_found_locations".equals(request.getAttribute("response"))) { %>
				<p>Nothing found. All locations are the following:</p>
			<% } else if(request.getAttribute("response") != null) { %>
				<p><span style="color:#FF0066;font-weight:bold;">Unexpected error.</span></p>
			<% }  %>
			
			<% 
				List<String> locations = (List<String>) request.getAttribute("locations");
				if(locations != null && locations.size() > 0) { 
			%>
			<ul>
				<% for(String l : locations) { %>
				<li><%= l %></li>
				<% } %>
			</ul>
			<% } %>
		</div>
	</td>
</div>

<jsp:include page="footer.jspf" />
