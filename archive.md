---
layout: default
title: Archive
---

<ul class="posts">
  {% for post in site.posts %}
    <li class="post-item">
      <h3 class="post-title">
        <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
      </h3>
      <time class="post-date" datetime="{{ post.date | date_to_xmlschema }}">{{ post.date | date_to_string }}</time>
    </li>
  {% endfor %}
</ul>