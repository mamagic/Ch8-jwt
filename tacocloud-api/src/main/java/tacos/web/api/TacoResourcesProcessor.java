package tacos.web.api;

import org.springframework.hateoas.server.mvc.WebMvcLinkBuilder;
import org.springframework.hateoas.PagedModel;
import org.springframework.hateoas.EntityModel;
import org.springframework.hateoas.server.RepresentationModelProcessor;
import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.*;
import org.springframework.stereotype.Component;

import tacos.Taco;

@Component
public class TacoResourcesProcessor implements RepresentationModelProcessor<PagedModel<EntityModel<Taco>>> {

  @Override
  public PagedModel<EntityModel<Taco>> process(PagedModel<EntityModel<Taco>> resources) {
	  resources.add(
		        WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(Taco.class))
		        .slash("recent")
		        .withRel("recents")
		    );
    
    return resources;
  }

}
