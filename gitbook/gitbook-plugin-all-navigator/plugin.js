function get_id(text) {
    return text.replace(/[,;. &%+*\/]/g, "_");
}

require(['gitbook', 'jQuery'], function(gitbook, $) {
    var showNumber;
    var showTitle;
    var headerSelector = '.book-header h1, .markdown-section h2, .markdown-section h3, .markdown-section h4';
    var noneSelector = '.markdown-section h2, .markdown-section h3, .markdown-section h4';
    var selector = noneSelector;
    anchors.options = {
        placement: 'left'
    }

    function removeAll() {
        $("#anchors-navbar").each(function() {
            $(this).remove();
        });

        $("#goTop").each(function() {
            $(this).remove();
        });
    }

    function scrollToAnchor(aid) {
        var aTag = $(aid);

        console.log(aTag);
        console.log(aTag.offset().top);

        $('html,body').animate({ scrollTop: aTag.offset().top }, 'slow');
    }

    function nav() {
        removeAll();

        var toc = [];
        var title_id = "";
        var title = "";
        var h2 = 0,
            h3 = 0,
            h4 = 0;

        $(selector).each(function() {

            var header = $(this);
            header.attr("id", get_id(header.text()));

            switch (header[0].nodeName) {
                case "H1":
                    title_id = header.attr("id");
                    title = header.text();
                    break;
                case "H2":
                    if (showNumber) {
                        h2 += 1;
                        h3 = h4 = 0;
                        text = h2 + ". " + header.text();
                        header.text(text);
                    }
                    toc.push({
                        name: header.text(),
                        url: header.attr("id"),
                        children: []
                    });
                    break;
                case "H3":
                    if (showNumber) {
                        h3 += 1;
                        h4 = 0;

                        text = h2 + "." + h3 + ". " + header.text();
                        header.text(text);
                    }
                    if (toc.length == 0) {
                        toc.push({ name: "none", url: "", children: [] });
                    }
                    toc[toc.length - 1].children.push({
                        name: header.text(),
                        url: header.attr("id"),
                        children: []
                    });
                    break;
                case "H4":
                    if (showNumber) {
                        h4 += 1;
                        text = h2 + "." + h3 + "." + h4 + ". " + header.text();
                        header.text(text);
                    }
                    if (toc.length == 0) {
                        toc.push({ name: "none", url: "", children: [] });
                    }
                    if (toc[toc.length - 1].children.length == 0) {
                        toc[toc.length - 1].children.push({ name: "none", url: "", children: [] });
                    }
                    toc[toc.length - 1].children[toc[toc.length - 1].children.length - 1].children.push({
                        name: header.text(),
                        url: header.attr("id"),
                        children: []
                    });
                    break;
                default:
                    break;
            }
        });

        if (toc.length == 0) {
            return;
        }

        console.log

        var html = "<div id='anchors-navbar'><i class='fa fa-anchor'></i><ul><p>" + title + "</p>";
        for (var i = 0; i < toc.length; i++) {
            html += "<li><a href='#" + toc[i].url + "'>" + toc[i].name + "</a></li>";
            if (toc[i].children.length > 0) {
                html += "<ul>"
                for (var j = 0; j < toc[i].children.length; j++) {
                    html += "<li><a href='#" + toc[i].children[j].url + "'>" + toc[i].children[j].name + "</a></li>";
                    if (toc[i].children[j].children.length > 0) {
                        html += "<ul>";
                        for (var k = 0; k < toc[i].children[j].children.length; k++) {
                            html += "<li><a href='#" + toc[i].children[j].children[k].url + "'>" + toc[i].children[j].children[k].name + "</a></li>";
                        }
                        html += "</ul>";
                    }
                }
                html += "</ul>"
            }
        }
        html += "</ul></div><a href='#" + toc[0].url + "' id='goTop'><i class='fa fa-arrow-up'></i></a>";

        $('.markdown-section').append(html);
    }

    gitbook.events.bind('start', function(e, config) {
        showNumber = config["all-navigator"].showNumber;
        showTitle = config["all-navigator"].showTitle;

        if (showTitle) {
            selector = headerSelector;
        }
    });

    gitbook.events.bind('page.change', function() {
        nav();
    });
});