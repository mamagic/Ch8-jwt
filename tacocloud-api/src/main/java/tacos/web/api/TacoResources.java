package tacos.web.api;

import java.util.List;
import java.util.Date;

import org.springframework.hateoas.CollectionModel;
import org.springframework.hateoas.RepresentationModel;
import org.springframework.hateoas.server.core.Relation;

import lombok.Getter;

import tacos.Ingredient;
import tacos.Taco;

@Relation(value = "taco", collectionRelation = "tacos")
public class TacoResources extends RepresentationModel<TacoResources> {

    @Getter
    private final String name;

    @Getter
    private final Date createAt;

    @Getter
    private final List<Ingredient> ingredients;

    public TacoResources(Taco taco) {
        this.name=taco.getName();
        this.createAt=taco.getCreatedAt();
        this.ingredients=taco.getIngredients();
    }
}