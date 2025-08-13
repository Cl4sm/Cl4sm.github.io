---
layout: default
title: blog
permalink: /blog/
---

<div class="terminal-header"><span class="prompt">$</span> cd <span class="filename">~/research/sefcom/clasm/blog</span> && ls</div>

<section class="blog-index">
  <ul class="blog-list">
  {% for post in site.posts %}
    {% if post.layout == 'blog_post' and post.private != true %}
    <li class="blog-list-item">
      <span class="powerline-arrow">»</span>
      <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
      <span class="blog-list-date">~ {{ post.date | date: "%b %-d, %Y" }}</span>
    </li>
    {% endif %}
  {% endfor %}
  </ul>
</section>

 
