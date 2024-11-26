$(function () {
    $(".controler li").click(function (e) {
      $(".controler li").removeClass("active");
      $(this).addClass("active");
      var clickVar = $(this).children("a").attr("href");
  
      switch (clickVar) {
        case "#one":
          $(".rings").attr("data-view", "one");
          break;
        case "#two":
          $(".rings").attr("data-view", "two");
          break;
        case "#three":
          $(".rings").attr("data-view", "three");
          break;
      }
    });
  });
  