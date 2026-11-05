frappe.query_reports["Passkey Enrollment"] = {
    filters: [
        { fieldname: "status", label: __("Status"), fieldtype: "Select",
          options: ["", "Enrolled", "Not enrolled", "In grace period", "Overdue"] },
        { fieldname: "role", label: __("Role"), fieldtype: "Link", options: "Role" },
        { fieldname: "include_disabled", label: __("Include Disabled Users"), fieldtype: "Check" },
    ],
    formatter: function (value, row, column, data, default_formatter) {
        value = default_formatter(value, row, column, data);
        if (column.fieldname === "status" && data) {
            const colour = { "Enrolled": "green", "Overdue": "red", "In grace period": "orange" }[data.status] || "gray";
            value = '<span class="indicator-pill ' + colour + '">' + value + "</span>";
        }
        return value;
    },
};
